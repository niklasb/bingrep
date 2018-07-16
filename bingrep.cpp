#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#include <cstring>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::pair;

void usage(std::ostream& out) {
    out << "Usage:" << endl;
    out << " 1) bingrep -f <filename>       [pattern]" << endl;
    out << " 2) bingrep -p <pid> [-i <num>] [pattern]" << endl;
    out << endl;
    out << "Pattern can be one of:" << endl;
    out << " -s <from addr> -e <to addr> [-w <pointer size, 4 or 8 (default)>]" << endl;
    out << " -b <hex>" << endl;
    out << " -a <ascii>" << endl;
    out << endl;
    out << "For type 2), -i specifies the number of dereferences before" << endl;
    out << "trying to match the pattern" << endl;
}

void usage_fail(const string& s="") {
    if (!s.empty())
        cerr << s << endl << endl;
    usage(cerr);
    exit(EXIT_FAILURE);
}

void die(const string& s) {
    cerr << s << endl;
    exit(EXIT_FAILURE);
}

void die_perror(const string& s) {
    perror(s.c_str());
    exit(EXIT_FAILURE);
}

struct Opts {
    string filename;
    int pid;
    int indirections;
    int pointer_size = 8;
    uint64_t from, to;
    string pattern;
} opts;

template <typename F>
void scan(const char* data, size_t size, F cb) {
    if (!opts.pattern.empty()) {
        const string& s = opts.pattern;
        for (size_t i = 0; i <= size - opts.pattern.size(); ++i) {
            if (!memcmp(data + i, s.data(), s.size()))
                cb(i);
        }
    } else if (opts.pointer_size == 4) {
        for (size_t i = 0; i <= size - 4; ++i) {
            uint32_t val = *reinterpret_cast<const uint32_t*>(data + i);
            if (val >= opts.from && val <= opts.to)
                cb(i);
        }
    } else if (opts.pointer_size == 8) {
        for (size_t i = 0; i <= size - 8; ++i) {
            uint64_t val = *reinterpret_cast<const uint64_t*>(data + i);
            if (val >= opts.from && val <= opts.to)
                cb(i);
        }
    } else {
        abort();
    }
}

void parse_opts(int argc, char** argv) {
    char c;
    while ((c = getopt (argc, argv, "f:p:i:s:e:w:b:a:h")) != -1) {
        switch (c) {
        case 'h':
            usage(cout);
            exit(EXIT_SUCCESS);
        case 'f':
            opts.filename = optarg;
            break;
        case 'p':
            opts.pid = atoi(optarg);
            break;
        case 'i':
            opts.indirections = atoi(optarg);
            if (opts.indirections < 0 || opts.indirections > 10)
                usage_fail("Invalid value for -i");
            break;
        case 's':
            opts.from = strtoull(optarg, nullptr, 16);
            break;
        case 'e':
            opts.to = strtoull(optarg, nullptr, 16);
            break;
        case 'w':
            opts.pointer_size = atoi(optarg);
            if (opts.pointer_size != 4 && opts.pointer_size != 8)
                usage_fail("Invalid value for -w (should be 4 or 8)");
            break;
        case 'b':
            cerr << "-b not implemented" << endl;
            usage_fail();
            break;
        case 'a':
            cerr << "-b not implemented" << endl;
            usage_fail();
            break;
        default:
            usage_fail();
        }
    }

    if ((!opts.filename.empty()) ^ (!!opts.pid) == 0) {
        usage_fail("Exactly one of -f or -p has to be specified.");
    }

    if (!opts.filename.empty() && opts.indirections != 0) {
        usage_fail("-i not supported in conjuction with -f.");
    }

    if ((opts.from || opts.to) ^ !opts.pattern.empty() == 0) {
        usage_fail("Either -s/-e or -b/-a need to be specified (but not both).");
    }

    if ((opts.from || opts.to) && opts.from > opts.to) {
        usage_fail("-s > -e, this makes no sense.");
    }

    if (opts.pointer_size < 8 && opts.to >= (1ull<<(8*opts.pointer_size))) {
        usage_fail("-e value is larger than pointer size.");
    }
}

void bingrep_file() {
    int fd = open(opts.filename.c_str(), 0);
    if (fd < 0) {
        die_perror("open failed");
    }

    auto size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        die_perror("lseek failed");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        die_perror("lseek (2) failed");
    }

    const char* map = reinterpret_cast<const char*>(
            mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (map == MAP_FAILED) {
        die_perror("mmap failed");
    }

    scan(map, size, [&](size_t offset) {
        cout << std::hex << std::setw(16) << std::setfill('0') << offset << endl;
    });
}

vector<pair<uint64_t, uint64_t>> parse_maps(int pid) {
    std::stringstream fname;
    fname << "/proc/" << pid << "/maps";
    std::ifstream f(fname.str());
    if (!f.good()) {
        die("Could not open maps file, are you root?");
    } string line;
    vector<pair<uint64_t, uint64_t>> res;
    while (getline(f, line)) {
        std::stringstream ss(line);
        uint64_t start, finish;
        char c;
        ss >> std::hex >> start >> c >> finish;
        res.emplace_back(start, finish);
    }
    return res;
}

void bingrep_proc() {
    std::stringstream fname;
    fname << "/proc/" << opts.pid << "/mem";
    std::ifstream f(fname.str());

    auto maps = parse_maps(opts.pid);
    int fd = open(fname.str().c_str(), 0);
    if (fd < 0) {
        die_perror("Could not open mem file, are you root?");
    }

    char * data = 0;
    for (const auto& map : maps) {
        uint64_t start = map.first, finish = map.second, size = finish - start;
        //cerr << "Scanning " << start << "-" << finish << endl;
        lseek(fd, start, SEEK_SET);
        data = new char[size];
        if (!data) {
            cerr << "FATAL: Could not allocate memory" << endl;
            exit(1);
        }
        size_t remaining = size;

        char* p = data;
        bool error = false;
        while (remaining) {
            ssize_t res = read(fd, p, remaining);
            if (res <= 0) {
                error = true;
                break;
            }
            p += res;
            remaining -= res;
        }

        if (error) {
            cerr << "Cannot read region "
                << std::hex << start << "-"
                << std::hex << finish << ", maybe the mapping changed. Skipping."
                << endl;
            continue;
        }

        scan(data, size, [&](size_t offset) {
            cout << std::hex << std::setw(16) << std::setfill('0') << (start + offset)
                    << endl;
        });
        delete[] data;
    }
}

int main(int argc, char **argv) {
    parse_opts(argc, argv);

    if (!opts.filename.empty()) {
        bingrep_file();
    } else {
        bingrep_proc();
    }
}
