#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <memory>
#include "semantic.h" // For PolicyConstraints

// Provenance & Source Classification
enum class BlocklistSourceType {
    BUILTIN_COMMON,         // High-risk baseline passwords hardcoded into compiler
    CONFIGURED_DICTIONARY,  // Custom configured dictionary file (e.g. dictionary.txt)
    BREACH_CORPUS,          // Separately supplied breach-derived dataset (e.g. breach_corpus.txt)
    CONTEXT_SPECIFIC,       // Organization or application specific forbidden terms
    CURATED_DATASET         // Curated 3,000 weak password dataset (OWASP ASVS V6.2.4)
};

struct BlocklistProvenance {
    std::string sourceId;
    BlocklistSourceType sourceType;
    std::string acquisitionDate;
    std::string license;
    std::string description;
    size_t rawLineCount = 0;
    size_t validEntryCount = 0;
    bool available = false;
    std::string statusMessage;
};

// Membership verification verdict
enum class MembershipStatus {
    DEFINITELY_NOT_PRESENT,     // Bloom filter negative: guaranteed not in blocklist
    EXACT_MATCH_CONFIRMED,       // Bloom positive confirmed by exact binary search in static table
    BLOOM_FALSE_POSITIVE,       // Bloom positive contradicted by exact verification (safely resolved)
    BLOCKLIST_UNAVAILABLE       // Corpus missing or empty
};

struct MembershipResult {
    MembershipStatus status = MembershipStatus::DEFINITELY_NOT_PRESENT;
    bool inBloomFilter = false;
    bool inExactTable = false;
    std::string matchedCanonicalKey;
    BlocklistSourceType sourceCategory = BlocklistSourceType::BUILTIN_COMMON;
    std::string diagnosticDetail;
};

// Mathematical parameters
struct BloomParameters {
    size_t n = 0;                       // Unique inserted canonical keys
    double targetFpr = 0.001;           // Target false-positive probability (default: 0.1%)
    uint64_t mBits = 0;                 // Bit array size
    size_t mBytes = 0;                  // Byte array size
    size_t k = 0;                       // Number of hash functions
    double theoreticalExpectedFpr = 0.0;// Calculated P = (1 - e^(-kn/m))^k
    bool valid = false;
    std::string calculationLog;
};

// Reusable Static Bloom Filter and Exact Verification Builder
class StaticBloomBuilder {
public:
    explicit StaticBloomBuilder(double targetFpr = 0.001);

    // Mathematical parameter calculation
    static BloomParameters computeParameters(size_t n, double targetFpr = 0.001);

    // Deterministic 64-bit hash functions
    static uint64_t hashFnv1a64(const char* data, size_t len);
    static uint64_t hashMurmurMix64(const char* data, size_t len);

    // Kirsch-Mitzenmacher bit probe index calculation
    static uint64_t getBitIndex(uint64_t h1, uint64_t h2, size_t probeIndex, uint64_t mBits);

    // Ingestion methods
    bool loadBuiltinCommon();
    bool loadDictionaryFile(const std::string& path);
    bool loadBreachCorpusFile(const std::string& path);
    bool loadCuratedDatasets(const std::string& baseDir = "");

    // Ingest arbitrary entry directly
    void addEntry(const std::string& entry, BlocklistSourceType srcType);

    // Canonicalization (trim, ASCII lower)
    static std::string canonicalizeKey(const std::string& raw);

    // Filter against active policy constraints (e.g. for OWASP V6.2.4 analysis)
    size_t countPolicyCompatibleEntries(const PolicyConstraints& constraints) const;

    // Filter synthesis
    bool build();

    // Query engine (runtime verification inside compiler / Agent 7)
    MembershipResult query(const std::string& candidateKey) const;

    // C++ Source Code Emission for target validator
    std::string emitStaticDataCpp() const;

    // JSON Manifest Emission for Dashboard Handoff
    bool emitManifestJson(const std::string& outputPath, const PolicyConstraints& constraints) const;

    // Accessors
    const BloomParameters& getParameters() const { return params; }
    const std::vector<BlocklistProvenance>& getProvenances() const { return provenances; }
    const std::vector<std::string>& getExactTable() const { return sortedExactKeys; }
    const std::vector<uint8_t>& getBitArray() const { return bitArray; }
    bool isSynthesized() const { return synthesized; }
    bool isAvailable() const { return params.n > 0 && synthesized; }
    size_t getTotalEmbeddedBytes() const;

private:
    double targetFpr;
    BloomParameters params;
    bool synthesized = false;

    // Deduplicated canonical storage
    std::set<std::string> uniqueCanonicalKeys;
    std::vector<std::string> sortedExactKeys;
    std::vector<uint8_t> bitArray;
    std::vector<BlocklistProvenance> provenances;

    void setBit(uint64_t bitIndex);
    bool testBit(uint64_t bitIndex) const;
};

#endif // BLOOM_FILTER_H

