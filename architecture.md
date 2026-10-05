regex architecture

                _score()
                   │
                   ▼
        Check global allowlist
                   │
           ┌───────┴───────┐
           │               │
         match           no match
           │               │
           ▼               ▼
      lower score      continue
                           │
                           ▼
                 Check Gitleaks
                 per-rule allowlist
                           │
                    ┌──────┴──────┐
                    │             │
                  match         no match
                    │             │
                    ▼             ▼
                 DROP ❌       continue
                                  │
                                  ▼
                         calculate normal score

When scoring a secret, first do your existing global checks, then check whether the specific Gitleaks rule says this secret is allowed. For now, check the actual secret rather than the entire regex match. If Gitleaks says it's allowed, completely discard it; don't just lower its score. Keep your existing stopwords behavior of multiplying the score by 0.4.