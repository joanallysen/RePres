from config_loader import load_secret_rules 

def main():
    print(load_secret_rules('gitleaks.toml')[1])

if __name__ == '__main__':
    main()