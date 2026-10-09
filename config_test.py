from config_loader import load_secret_rules 

def main():
    # array 0 for showing secret rules ajsut wrnd 1 for failure
    # every secret rule is defaulted to 0.85 as of right now
    rules, failure, dict = load_secret_rules('gitleaks.toml')
    with open("results/config_test_results.txt", "w", encoding="utf-8") as f:
        f.write("GITLEAKS CONFIG TEST\n")

        f.write(f"SUCCESSFUL RULES: {len(rules)}\n")
        f.write(f"FAILED RULES: {len(failure)}\n\n")

        # Successful rules
        f.write("SUCCESSFUL RULES\n")

        for i, rule in enumerate(rules, 1):
            f.write(f"{i}. {rule.id}\n")
            f.write(f"   Description: {rule.description}\n")
            f.write(f"   Regex: {rule.regex}\n")
            f.write(f"   Secret group: {rule.secret_group}\n")
            f.write(f"   Score: {rule.score}\n")
            f.write(f"   Entropy: {rule.entropy}\n")
            f.write("\n")

if __name__ == '__main__':
    main()