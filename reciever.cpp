#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
using namespace std;

const int RECORD_SIZE = 512;
const char* LOG_FILE = "receiver_log.txt";

enum PacketType : uint8_t {
    FILE_HDR = 1,
    FILE_HDR_ACK,
    DATA_PACKET,
    IS_BLAST_OVER,
    REC_MISS,
    DISCONNECT
};

mutex mtx;
map<int, vector<vector<uint8_t>>> storage;
map<int, uint32_t> blast_start_map;
bool done = false;
bool disconnect_received = false;
string output_file = "received.txt";

double drop_prob = 0.0;
random_device rd;
mt19937 rng(rd());
uniform_real_distribution<double> dist(0.0, 1.0);

// ---- Stats tracking ----
atomic<uint64_t> total_records_expected = 0;
atomic<uint64_t> total_records_received = 0;
atomic<uint64_t> total_records_dropped = 0;
chrono::steady_clock::time_point start_time, end_time;
bool started = false;

uint16_t checksum(const uint8_t* data, int n) {
    uint32_t s = 0;
    for (int i = 0; i < n; i++) s += data[i];
    return s & 0xFFFF;
}

void logf(const string& s) {
    ofstream f(LOG_FILE, ios::app);
    f << s << std::endl;
}

bool garbler_drop() { return dist(rng) < drop_prob; }

// Writer: write each record at its absolute offset (base + index)
void writer_thread() {
    // Wait until disconnect signal (sender ended)
    while (!disconnect_received)
        this_thread::sleep_for(300ms);

    lock_guard<mutex> lk(mtx);
    ofstream fout(output_file, ios::binary | ios::trunc);
    if (!fout.is_open()) {
        logf("Writer thread: cannot open output file for final write");
        return;
    }

    // For every blast in storage, use its base (blast_start_map) to compute absolute offsets
    for (auto& entry : storage) {
        int bid = entry.first;
        auto &recs = entry.second;
        uint32_t base = 1;
        if (blast_start_map.count(bid)) base = blast_start_map[bid];
        // write each present record at correct file offset
        for (size_t i = 0; i < recs.size(); ++i) {
            auto &rec = recs[i];
            if (rec.empty()) continue;
            uint64_t abs_rec_no = (uint64_t)base + (uint64_t)i; // absolute record number (1-based)
            uint64_t filepos = (abs_rec_no - 1) * (uint64_t)RECORD_SIZE;
            fout.seekp((streamoff)filepos, ios::beg);
            fout.write((char*)rec.data(), RECORD_SIZE);
        }
    }

    fout.close();
    logf("Writer thread: Final file write completed.");
}

int main(int argc, char* argv[]) {
    int port = 5000;
    if (argc > 1) port = stoi(argv[1]);
    if (argc > 2) drop_prob = stod(argv[2]);
    ofstream(LOG_FILE, ios::trunc);

    logf("Starting receiver on port " + to_string(port) + " with drop probability " + to_string(drop_prob));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(sock, (sockaddr*)&addr, sizeof(addr));

    thread t(writer_thread);
    uint8_t buf[65536];
    sockaddr_in src{};
    socklen_t sl = sizeof(src);

    while (true) {
        int r = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &sl);
        if (r <= 0) continue;

        uint8_t type = buf[0];
        if (type == FILE_HDR) {
            uint32_t fs = ntohl(*(uint32_t*)(buf + 1));
            logf("FILE_HDR received (" + to_string(fs) + " bytes)");
            uint8_t ack[] = {FILE_HDR_ACK};
            sendto(sock, ack, 1, 0, (sockaddr*)&src, sl);

            if (!started) {
                start_time = chrono::steady_clock::now();
                started = true;
            }
        } 
        else if (type == DATA_PACKET) {
            uint32_t bid = ntohl(*(uint32_t*)(buf + 1));
            uint32_t pid = ntohl(*(uint32_t*)(buf + 5));
            uint32_t start = ntohl(*(uint32_t*)(buf + 9));
            uint16_t nrec = ntohs(*(uint16_t*)(buf + 13));

            uint16_t cs_recv = ntohs(*(uint16_t*)(buf + r - 2));
            uint16_t cs_calc = checksum(buf, r - 2);
            if (cs_recv != cs_calc) {
                logf("Checksum fail pkt " + to_string(pid));
                total_records_dropped += nrec;
                continue;
            }

            lock_guard<mutex> lk(mtx);
            if (!blast_start_map.count(bid)) blast_start_map[bid] = start;
            uint32_t base = blast_start_map[bid];

            if (start < base) {
                int shift = (int)(base - start);
                auto &blast = storage[bid];
                int oldsz = (int)blast.size();
                blast.resize(oldsz + shift);
                for (int i = oldsz - 1; i >= 0; --i) {
                    blast[i + shift] = std::move(blast[i]);
                }
                for (int i = 0; i < shift; ++i) blast[i].clear();
                base = start;
                blast_start_map[bid] = base;
            }

            int local_index = (int)start - (int)base;
            if (local_index < 0) local_index = 0;
            auto& blast = storage[bid];
            if ((int)blast.size() < local_index + nrec)
                blast.resize(local_index + nrec);

            int offset = 15;
            for (int i = 0; i < nrec; i++) {
                total_records_expected++;
                if (garbler_drop()) {
                    total_records_dropped++;
                    logf("Dropped record " + to_string(start + i) + " (blast " + to_string(bid) + ")");
                    continue;
                }
                blast[local_index + i].assign(buf + offset + i * RECORD_SIZE, buf + offset + (i + 1) * RECORD_SIZE);
                total_records_received++;
            }

            logf("Blast " + to_string(bid) + " pkt " + to_string(pid) +
                 " recs " + to_string(start) + "-" + to_string(start + nrec - 1));
        }

        else if (type == IS_BLAST_OVER) {
            uint32_t bid = ntohl(*(uint32_t*)(buf + 1));
            logf("IS_BLAST_OVER from blast " + to_string(bid));

            vector<pair<uint32_t, uint32_t>> misses;
            {
                lock_guard<mutex> lk(mtx);
                auto it = storage.find(bid);
                if (it != storage.end()) {
                    auto& recs = it->second;
                    uint32_t base = blast_start_map[bid];
                    for (int i = 0; i < (int)recs.size();) {
                        if (recs[i].empty()) {
                            int j = i;
                            while (j < (int)recs.size() && recs[j].empty()) j++;
                            misses.push_back({base + i, base + j - 1});
                            i = j;
                        } else i++;
                    }
                }
            }

            vector<uint8_t> resp;
            resp.push_back(REC_MISS);
            uint32_t nb = htonl(bid);
            resp.insert(resp.end(), (uint8_t*)&nb, (uint8_t*)&nb + 4);
            uint16_t miss_count = htons(misses.size());
            resp.insert(resp.end(), (uint8_t*)&miss_count, (uint8_t*)&miss_count + 2);
            for (auto [st, en] : misses) {
                uint32_t s = htonl(st), e = htonl(en);
                resp.insert(resp.end(), (uint8_t*)&s, (uint8_t*)&s + 4);
                resp.insert(resp.end(), (uint8_t*)&e, (uint8_t*)&e + 4);
            }

            sendto(sock, resp.data(), resp.size(), 0, (sockaddr*)&src, sl);

            string log_msg = "REC_MISS sent for blast " + to_string(bid) + 
                            " (" + to_string(misses.size()) + " ranges)";
            if (!misses.empty()) {
                log_msg += ": ";
                for (auto [st, en] : misses)
                    log_msg += "[" + to_string(st) + "-" + to_string(en) + "] ";
            }
            logf(log_msg);

            if (misses.empty()) {
                lock_guard<mutex> lk(mtx);
                logf("Blast " + to_string(bid) + " completed and cleared from storage");
            }
        }

        else if (type == DISCONNECT) {
            logf("DISCONNECT received");
            disconnect_received = true;
            done = true;
            end_time = chrono::steady_clock::now();

            double secs = chrono::duration<double>(end_time - start_time).count();
            double throughput_kb = (total_records_received * RECORD_SIZE) / (1024.0 * secs);
            double loss_pct = (total_records_expected == 0)
                              ? 0.0
                              : (100.0 * total_records_dropped / total_records_expected);

            logf("---- TRANSFER SUMMARY ----");
            logf("Total records expected : " + to_string(total_records_expected.load()));
            logf("Total records received : " + to_string(total_records_received.load()));
            logf("Total records dropped  : " + to_string(total_records_dropped.load()));
            logf("Throughput (KB/s)      : " + to_string(throughput_kb));
            logf("Packet loss (%)        : " + to_string(loss_pct));
            logf("---------------------------");

            break;
        }
    }

    t.join(); // ensures file fully written before closing
    close(sock);
    logf("Receiver shutdown cleanly after full file write.");
}
