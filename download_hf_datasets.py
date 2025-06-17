#!/usr/bin/env python3
"""
Download and convert HuggingFace prompt injection datasets for Goose security benchmarks
"""

import json
import os
import sys
from typing import List, Dict, Any
import pandas as pd

try:
    from datasets import load_dataset
    import requests
except ImportError:
    print("Required packages not installed. Run: pip install datasets pandas requests")
    sys.exit(1)

def convert_to_goose_format(
    text: str, 
    label: str, 
    dataset_name: str, 
    index: int,
    category: str = "unknown",
    description: str = ""
) -> Dict[str, Any]:
    """Convert a dataset entry to Goose PromptInjectionTestCase format"""
    
    # Map various label formats to threat levels
    threat_level_mapping = {
        # Binary labels
        "INJECTION": "High",
        "SAFE": "Safe",
        "injection": "High", 
        "safe": "Safe",
        "malicious": "High",
        "benign": "Safe",
        "harmful": "High",
        "harmless": "Safe",
        
        # Numeric labels
        "1": "High",
        "0": "Safe",
        1: "High",
        0: "Safe",
        
        # Multi-class labels
        "jailbreak": "High",
        "prompt_injection": "High",
        "normal": "Safe",
        "legitimate": "Safe",
    }
    
    # Normalize label
    if isinstance(label, (int, float)):
        label_key = int(label)
    else:
        label_key = str(label).lower().strip()
    
    threat_level = threat_level_mapping.get(label_key, "Medium")
    
    return {
        "id": f"{dataset_name}_{index}",
        "input": text.strip(),
        "expected_threat_level": threat_level,
        "category": category,
        "description": description or f"Test case from {dataset_name}",
        "source": f"huggingface_{dataset_name}"
    }

def download_aestera_dataset() -> List[Dict[str, Any]]:
    """Download aestera/prompt_injection_payloads dataset"""
    print("Downloading aestera/prompt_injection_payloads...")
    
    try:
        dataset = load_dataset("aestera/prompt_injection_payloads", split="train")
        test_cases = []
        
        for i, example in enumerate(dataset):
            # This dataset contains various prompt injection payloads
            # Assuming all entries are malicious (injection attempts)
            test_case = convert_to_goose_format(
                text=example.get("text", example.get("prompt", example.get("payload", ""))),
                label="INJECTION",  # All payloads are injection attempts
                dataset_name="aestera_payloads",
                index=i,
                category="prompt_injection",
                description="Prompt injection payload from aestera dataset"
            )
            test_cases.append(test_case)
            
        print(f"✓ Downloaded {len(test_cases)} test cases from aestera/prompt_injection_payloads")
        return test_cases
        
    except Exception as e:
        print(f"✗ Failed to download aestera dataset: {e}")
        return []

def download_mindgard_dataset() -> List[Dict[str, Any]]:
    """Download Mindgard/evaded-prompt-injection-and-jailbreak-samples dataset"""
    print("Downloading Mindgard/evaded-prompt-injection-and-jailbreak-samples...")
    
    try:
        dataset = load_dataset("Mindgard/evaded-prompt-injection-and-jailbreak-samples", split="train")
        test_cases = []
        
        for i, example in enumerate(dataset):
            # This dataset contains evaded prompt injections and jailbreaks
            # These are sophisticated attacks that have bypassed defenses
            
            # Extract the prompt text (field names may vary)
            text = ""
            for field in ["prompt", "text", "input", "attack", "payload"]:
                if field in example and example[field]:
                    text = example[field]
                    break
            
            if not text:
                continue
                
            # Determine category based on available metadata
            category = "advanced_injection"
            if "jailbreak" in str(example).lower():
                category = "jailbreak"
            elif "injection" in str(example).lower():
                category = "prompt_injection"
                
            test_case = convert_to_goose_format(
                text=text,
                label="INJECTION",  # All samples are successful attacks
                dataset_name="mindgard_evaded",
                index=i,
                category=category,
                description="Evaded prompt injection/jailbreak from Mindgard dataset"
            )
            test_cases.append(test_case)
            
        print(f"✓ Downloaded {len(test_cases)} test cases from Mindgard dataset")
        return test_cases
        
    except Exception as e:
        print(f"✗ Failed to download Mindgard dataset: {e}")
        return []

def download_additional_datasets() -> List[Dict[str, Any]]:
    """Download additional popular prompt injection datasets"""
    additional_cases = []
    
    # Try some other popular datasets
    datasets_to_try = [
        ("deepset/prompt-injections", "deepset"),
        ("JasperLS/prompt-injections", "jasperls"),
        ("qualifire/Qualifire-prompt-injection-benchmark", "qualifire"),
    ]
    
    for dataset_name, short_name in datasets_to_try:
        try:
            print(f"Trying to download {dataset_name}...")
            dataset = load_dataset(dataset_name, split="train")
            
            for i, example in enumerate(dataset):
                # Try to extract text and label from various field names
                text = ""
                label = "INJECTION"  # Default assumption
                
                # Common field names for text
                for text_field in ["text", "prompt", "input", "query", "instruction"]:
                    if text_field in example and example[text_field]:
                        text = example[text_field]
                        break
                
                # Common field names for labels
                for label_field in ["label", "is_injection", "malicious", "harmful", "target"]:
                    if label_field in example and example[label_field] is not None:
                        label = example[label_field]
                        break
                
                if text:
                    test_case = convert_to_goose_format(
                        text=text,
                        label=label,
                        dataset_name=short_name,
                        index=i,
                        category="prompt_injection",
                        description=f"Test case from {dataset_name}"
                    )
                    additional_cases.append(test_case)
            
            print(f"✓ Downloaded {len([c for c in additional_cases if short_name in c['source']])} cases from {dataset_name}")
            
        except Exception as e:
            print(f"✗ Failed to download {dataset_name}: {e}")
            continue
    
    return additional_cases

def save_datasets():
    """Download all datasets and save them in formats that Goose can load"""
    
    # Create datasets directory
    os.makedirs("datasets", exist_ok=True)
    
    all_test_cases = []
    
    # Download each dataset
    aestera_cases = download_aestera_dataset()
    mindgard_cases = download_mindgard_dataset()
    additional_cases = download_additional_datasets()
    
    all_test_cases.extend(aestera_cases)
    all_test_cases.extend(mindgard_cases)
    all_test_cases.extend(additional_cases)
    
    if not all_test_cases:
        print("No test cases downloaded. Exiting.")
        return
    
    print(f"\nTotal test cases downloaded: {len(all_test_cases)}")
    
    # Save in different formats for the Goose dataset loader
    
    # 1. JSON format (single file)
    json_path = "datasets/huggingface_prompt_injection.json"
    with open(json_path, 'w') as f:
        json.dump({"test_cases": all_test_cases}, f, indent=2)
    print(f"✓ Saved {len(all_test_cases)} test cases to {json_path}")
    
    # 2. JSONL format (one JSON object per line)
    jsonl_path = "datasets/huggingface_prompt_injection.jsonl"
    with open(jsonl_path, 'w') as f:
        for case in all_test_cases:
            f.write(json.dumps(case) + '\n')
    print(f"✓ Saved {len(all_test_cases)} test cases to {jsonl_path}")
    
    # 3. CSV format
    csv_path = "datasets/huggingface_prompt_injection.csv"
    df = pd.DataFrame(all_test_cases)
    df.to_csv(csv_path, index=False)
    print(f"✓ Saved {len(all_test_cases)} test cases to {csv_path}")
    
    # 4. Separate files by dataset source
    by_source = {}
    for case in all_test_cases:
        source = case['source']
        if source not in by_source:
            by_source[source] = []
        by_source[source].append(case)
    
    for source, cases in by_source.items():
        source_path = f"datasets/{source}.json"
        with open(source_path, 'w') as f:
            json.dump({"test_cases": cases}, f, indent=2)
        print(f"✓ Saved {len(cases)} test cases from {source} to {source_path}")
    
    # Print summary statistics
    print(f"\n=== Dataset Summary ===")
    print(f"Total test cases: {len(all_test_cases)}")
    
    # By source
    print("\nBy source:")
    for source, cases in by_source.items():
        print(f"  {source}: {len(cases)} cases")
    
    # By threat level
    by_threat = {}
    for case in all_test_cases:
        threat = case['expected_threat_level']
        by_threat[threat] = by_threat.get(threat, 0) + 1
    
    print("\nBy threat level:")
    for threat, count in sorted(by_threat.items()):
        print(f"  {threat}: {count} cases")
    
    # By category
    by_category = {}
    for case in all_test_cases:
        category = case['category']
        by_category[category] = by_category.get(category, 0) + 1
    
    print("\nBy category:")
    for category, count in sorted(by_category.items()):
        print(f"  {category}: {count} cases")

if __name__ == "__main__":
    print("=== HuggingFace Prompt Injection Dataset Downloader ===")
    print("This script will download prompt injection datasets and convert them to Goose format.")
    print()
    
    save_datasets()
    
    print("\n=== Next Steps ===")
    print("1. The datasets have been saved in the 'datasets/' directory")
    print("2. Update your Rust code to load these files")
    print("3. Run your benchmark with the expanded test suite")
    print("4. The dataset loader will automatically pick up files from these locations:")
    print("   - datasets/huggingface_prompt_injection.json")
    print("   - datasets/huggingface_prompt_injection.jsonl") 
    print("   - datasets/huggingface_prompt_injection.csv")