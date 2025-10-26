// sender.cpp  (updated minimal retransmit + logging)
// Replace your previous sender with this file. Minimal changes from your version.

#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <condition_variable>
using namespace std;

const int RECORD_SIZE = 512;
const int MAX_RECORDS_PER_PACKET = 16;
const int RECORDS_PER_BLAST = 500;
const char* LOG_FILE = "sender_log.txt";

// ---------------------- Packet Types ----------------------
enum PacketType : uint8_t {
    FILE_HDR = 1,
    FILE_HDR_ACK,
    DATA_PACKET,
    IS_BLAST_OVER,
    REC_MISS,
    DISCONNECT
};

// ---------------------- Structs ----------------------
struct Blast {
    int id;
    int start_rec;
    int end_rec;
    vector<vector<uint8_t>> records;
};

// ---------------------- Globals ----------------------
mutex mtx;
condition_variable cv;
bool buffer_ready = false;
Blast current_blast;

// ---------------------- Utils ----------------------
uint16_t checksum(const vector<uint8_t>& data) {
    uint32_t s = 0;
    for (auto x : data) s += x;
    return s & 0xFFFF;
}

void logf(const string& s) {
    ofstream f(LOG_FILE, ios::app);
    f << s << "\n";
}

// ---------------------- Reader Thread ----------------------
void reader_thread(const string& filename, int start, int end) {
    ifstream fin(filename, ios::binary);
    fin.seekg((long long)(start - 1) * RECORD_SIZE);

    current_blast.records.clear();
    for (int i = start; i <= end; i++) {
        vector<uint8_t> rec(RECORD_SIZE, ' ');
        fin.read((char*)rec.data(), RECORD_SIZE);
        current_blast.records.push_back(rec);
    }
    fin.close();

    lock_guard<mutex> lk(mtx);
    buffer_ready = true;
    cv.notify_all();
}

// ---------------------- Helpers to send packets ----------------------
bool send_udp(int sock, const vector<uint8_t>& pkt, const sockaddr_in& addr) {
    ssize_t s = sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&addr, sizeof(addr));
    return s == (ssize_t)pkt.size();
}

// helper to pack & send a contiguous range of local record indices [lstart..lend]
void send_records_range(int sock, const sockaddr_in& addr, int blast_id, int &packet_id_counter,
                        int local_start_idx, int local_end_idx) {
    // local indices are 0-based inside current_blast.records
    int idx = local_start_idx;
    while (idx <= local_end_idx) {
        int take = min(MAX_RECORDS_PER_PACKET, local_end_idx - idx + 1);
        // build packet
        vector<uint8_t> pkt;
        pkt.push_back(DATA_PACKET);
        uint32_t bid_n = htonl((uint32_t)blast_id); pkt.insert(pkt.end(), (uint8_t*)&bid_n, (uint8_t*)&bid_n + 4);
        uint32_t pid_n = htonl((uint32_t)++packet_id_counter); pkt.insert(pkt.end(), (uint8_t*)&pid_n, (uint8_t*)&pid_n + 4);
        uint32_t abs_start = htonl((uint32_t)(current_blast.start_rec + idx)); pkt.insert(pkt.end(), (uint8_t*)&abs_start, (uint8_t*)&abs_start + 4);
        uint16_t count_n = htons((uint16_t)take); pkt.insert(pkt.end(), (uint8_t*)&count_n, (uint8_t*)&count_n + 2);
        for (int j = 0; j < take; ++j) {
            auto &rec = current_blast.records[idx + j];
            pkt.insert(pkt.end(), rec.begin(), rec.end());
        }
        uint16_t cs = htons(checksum(pkt));
        pkt.insert(pkt.end(), (uint8_t*)&cs, (uint8_t*)&cs + 2);

        bool ok = send_udp(sock, pkt, addr);
        if (ok) {
            int abs_st = current_blast.start_rec + idx;
            int abs_en = current_blast.start_rec + idx + take - 1;
            logf("Retransmit Blast " + to_string(blast_id) + " pkt " + to_string(ntohl(pid_n)) +
                 " recs " + to_string(abs_st) + "-" + to_string(abs_en));
        } else {
            logf("Retransmit Blast " + to_string(blast_id) + " pkt send FAILED");
        }

        idx += take;
    }
}

// ---------------------- Main ----------------------
int main(int argc, char* argv[]) {
    if (argc < 4) {
        cerr << "Usage: ./sender <file> <ip> <port>\n";
        return 0;
    }
    ofstream(LOG_FILE, ios::trunc);

    string file = argv[1];
    string ip = argv[2];
    int port = stoi(argv[3]);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    addr.sin_port = htons(port);

    // ---- FILE HEADER ----
    ifstream fin(file, ios::binary | ios::ate);
    int filesize = fin.tellg();
    fin.close();
    vector<uint8_t> hdr;
    hdr.push_back(FILE_HDR);
    uint32_t fs = htonl(filesize);
    hdr.insert(hdr.end(), (uint8_t*)&fs, (uint8_t*)&fs + 4);
    sendto(sock, hdr.data(), hdr.size(), 0, (sockaddr*)&addr, sizeof(addr));
    logf("Sent FILE_HDR (" + to_string(filesize) + " bytes)");

    uint8_t buf[65536];
    socklen_t sl = sizeof(addr);
    // wait for FILE_HDR_ACK (we assume receiver responds immediately)
    recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&addr, &sl);

    int total_records = (filesize + RECORD_SIZE - 1) / RECORD_SIZE;
    int blast_id = 0;
    int global_packet_id = 0;

    for (int cur = 1; cur <= total_records; cur += RECORDS_PER_BLAST) {
        blast_id++;
        int start = cur;
        int end = min(cur + RECORDS_PER_BLAST - 1, total_records);
        current_blast = {blast_id, start, end, {}};

        // Spawn reader thread
        thread t(reader_thread, file, start, end);

        unique_lock<mutex> lk(mtx);
        cv.wait(lk, [] { return buffer_ready; });
        buffer_ready = false;
        lk.unlock();

        logf("Blast " + to_string(blast_id) + " START (" + to_string(start) + "-" + to_string(end) + ")");

        // Send packets (first pass)
        int pkt_id = 0;
        for (int i = 0; i < (int)current_blast.records.size(); i += MAX_RECORDS_PER_PACKET) {
            int count = min(MAX_RECORDS_PER_PACKET, (int)current_blast.records.size() - i);
            vector<uint8_t> pkt;
            pkt.push_back(DATA_PACKET);

            uint32_t bid = htonl(blast_id);
            uint32_t pid = htonl(++pkt_id);
            uint32_t st = htonl(start + i);
            uint16_t c = htons(count);

            pkt.insert(pkt.end(), (uint8_t*)&bid, (uint8_t*)&bid + 4);
            pkt.insert(pkt.end(), (uint8_t*)&pid, (uint8_t*)&pid + 4);
            pkt.insert(pkt.end(), (uint8_t*)&st, (uint8_t*)&st + 4);
            pkt.insert(pkt.end(), (uint8_t*)&c, (uint8_t*)&c + 2);

            for (int j = 0; j < count; j++)
                pkt.insert(pkt.end(), current_blast.records[i + j].begin(), current_blast.records[i + j].end());

            uint16_t cs = htons(checksum(pkt));
            pkt.insert(pkt.end(), (uint8_t*)&cs, (uint8_t*)&cs + 2);

            sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&addr, sizeof(addr));
            logf("Blast " + to_string(blast_id) + " Sent pkt " + to_string(pkt_id) +
                 " recs " + to_string(start + i) + "-" + to_string(start + i + count - 1));
        }

        // ---- IS_BLAST_OVER ----
        vector<uint8_t> over;
        over.push_back(IS_BLAST_OVER);
        uint32_t bid = htonl(blast_id);
        over.insert(over.end(), (uint8_t*)&bid, (uint8_t*)&bid + 4);
        sendto(sock, over.data(), over.size(), 0, (sockaddr*)&addr, sizeof(addr));
        logf("Blast " + to_string(blast_id) + " IS_BLAST_OVER sent");

        // ---- WAIT FOR REC_MISS & retransmit loop ----
        struct timeval tv {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        while (true) {
            int r = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&addr, &sl);
            if (r <= 0) {
                // timeout: retransmit IS_BLAST_OVER
                sendto(sock, over.data(), over.size(), 0, (sockaddr*)&addr, sizeof(addr));
                logf("Blast " + to_string(blast_id) + " IS_BLAST_OVER retransmit (timeout)");
                continue;
            }
            if (buf[0] != REC_MISS) continue;

            // parse REC_MISS: type(1) blast_id(4) miss_count(2) pairs (st,en)...
            if (r < 7) continue;
            uint32_t recv_bid = ntohl(*(uint32_t*)(buf + 1));
            if ((int)recv_bid != blast_id) continue;
            uint16_t miss_count = ntohs(*(uint16_t*)(buf + 5));
            logf("Blast " + to_string(blast_id) + " REC_MISS received: " + to_string(miss_count) + " ranges");

            if (miss_count == 0) {
                // done with this blast
                break;
            }

            // parse ranges and retransmit each
            vector<pair<uint32_t,uint32_t>> ranges;
            size_t pos = 7;
            for (int i = 0; i < miss_count && pos + 8 <= (size_t)r; ++i) {
                uint32_t st = ntohl(*(uint32_t*)(buf + pos)); pos += 4;
                uint32_t en = ntohl(*(uint32_t*)(buf + pos)); pos += 4;
                ranges.emplace_back(st, en);
            }

            // log ranges
            string ranges_line = "Blast " + to_string(blast_id) + " missing ranges: ";
            for (auto &pr : ranges) ranges_line += "[" + to_string(pr.first) + "-" + to_string(pr.second) + "] ";
            logf(ranges_line);

            // retransmit each missing range
            for (auto &pr : ranges) {
                uint32_t st_abs = pr.first;
                uint32_t en_abs = pr.second;
                // convert to local indices (0-based)
                int lstart = (int)(st_abs - current_blast.start_rec);
                int lend   = (int)(en_abs - current_blast.start_rec);
                if (lstart < 0) lstart = 0;
                if (lend >= (int)current_blast.records.size()) lend = (int)current_blast.records.size()-1;
                // send in packets up to MAX_RECORDS_PER_PACKET
                send_records_range(sock, addr, blast_id, global_packet_id, lstart, lend);
            }

            // after retransmissions, resend IS_BLAST_OVER
            sendto(sock, over.data(), over.size(), 0, (sockaddr*)&addr, sizeof(addr));
            logf("Blast " + to_string(blast_id) + " IS_BLAST_OVER resent after retransmits");
            // loop to wait for next REC_MISS (which may be empty)
        }

        t.join();
        logf("Blast " + to_string(blast_id) + " END\n");
    }

    uint8_t disc[] = {DISCONNECT};
    sendto(sock, disc, 1, 0, (sockaddr*)&addr, sizeof(addr));
    logf("Transfer complete. DISCONNECT sent.");
    close(sock);
    return 0;
}
