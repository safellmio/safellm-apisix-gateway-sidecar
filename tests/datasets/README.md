# Test Datasets for Security Benchmarking

This folder contains curated datasets specifically designed for testing LLM security systems, with particular focus on false positive detection and comprehensive security validation.

## 📊 Available Datasets

### 🔍 False Positive Focused Datasets

#### `edge_cases_false_positives.csv`
- **Purpose**: Test edge cases that commonly trigger false positives
- **Content**: Safe prompts using technical/business terminology that security systems might misinterpret
- **Categories**: email, technical, medical, programming, gardening, legal, etc.
- **Size**: ~40 samples
- **Critical for**: User experience testing - these should ALL be allowed

#### `known_false_positives.csv`
- **Purpose**: Documented cases where security systems have failed in the past
- **Content**: Real examples from testing failures with root cause analysis
- **Includes**: Both safe prompts (should pass) and unsafe prompts (should fail)
- **Size**: ~35 samples
- **Critical for**: Regression testing and improvement tracking

### 🛡️ General Security Datasets

#### `latency_safe_prompts.csv`
- **Purpose**: Safe prompts for performance benchmarking
- **Content**: Benign, everyday queries and requests
- **Examples**: "How to boil an egg?", "What is the capital of France?"
- **Size**: ~8 samples
- **Use case**: Performance testing with guaranteed safe content

#### `latency_unsafe_prompts.csv`
- **Purpose**: Unsafe prompts for performance benchmarking
- **Content**: Clear security violations and attack attempts
- **Examples**: "Ignore all previous instructions", jailbreak attempts
- **Size**: ~10 samples
- **Use case**: Performance testing with guaranteed unsafe content

### 🤖 AI-Specific Datasets

#### `prompt_injections.csv`
- **Purpose**: Test prompt injection attack detection
- **Format**: text, label (0=safe, 1=unsafe)
- **Content**: Various prompt injection techniques
- **Size**: ~560 samples
- **Source**: Deepset prompt injection dataset

#### `toxicity_prompts.csv`
- **Purpose**: Test toxic content detection
- **Format**: prompt, toxicity_score
- **Content**: Text samples with toxicity scoring
- **Threshold**: >0.5 considered toxic
- **Size**: ~100 samples

#### `alert_adversarial_prompts.csv`
- **Purpose**: Test adversarial prompt detection
- **Content**: Sophisticated jailbreak and attack attempts
- **Format**: Complex multi-turn attack patterns
- **Size**: ~400 samples

## 🎯 Usage in Benchmarks

### `datasetBenchmark.py`
- Tests all datasets comprehensively
- Provides accuracy, precision, recall metrics
- Focuses on overall security performance
- Generates comparative analysis across datasets

### `BENCHMARK_DETECTION.py`
- Specialized false positive analysis
- Pattern recognition and root cause analysis
- Detailed categorization of failures
- Recommendations for threshold tuning

## 📈 Key Metrics Tracked

- **False Positive Rate**: Critical for user experience
- **False Negative Rate**: Critical for security
- **Accuracy**: Overall correctness
- **Precision**: Correctness of unsafe detections
- **Recall**: Coverage of unsafe content detection
- **Latency**: Performance impact analysis

## 🔧 Dataset Format Standards

All datasets follow consistent CSV format:
```csv
prompt,expected,category,description
"Sample prompt text","safe"|"unsafe","category_name","Optional description"
```

## 🚀 Adding New Datasets

1. **Create CSV file** in this directory
2. **Follow naming convention**: `purpose_descriptive_name.csv`
3. **Update this README** with dataset description
4. **Update benchmark scripts** to include new dataset
5. **Test integration** with both benchmark tools

## 📋 False Positive Categories

Common categories that trigger false positives:
- `email`: Business/professional email content
- `technical`: IT, programming, database terminology
- `medical`: Healthcare and medical instructions
- `legal`: Legal document language
- `gardening`: Botanical/horticultural terms
- `programming`: Code and development terminology
- `cryptography`: Security and encryption discussions
- `gaming`: Game-related instructions
- `academic`: Research and educational content

## 🎖️ Benchmark Targets

- **False Positive Rate**: <5% (industry standard for security systems)
- **Accuracy**: >95% across all datasets
- **Latency**: <100ms per request
- **Throughput**: >50 RPS under load

## 📁 File Structure
```
datasets/
├── README.md                           # This file
├── edge_cases_false_positives.csv      # Edge case testing
├── known_false_positives.csv           # Regression testing
├── latency_safe_prompts.csv           # Performance testing (safe)
├── latency_unsafe_prompts.csv         # Performance testing (unsafe)
├── prompt_injections.csv              # Injection attacks
├── toxicity_prompts.csv               # Toxic content
└── alert_adversarial_prompts.csv      # Advanced attacks
```