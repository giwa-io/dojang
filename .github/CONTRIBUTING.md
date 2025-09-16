# Contributing to Dojang

Welcome!  
Thank you for considering contributing to **Dojang**, the trust layer of the Giwa ecosystem.  
This document explains how to set up your development environment, contribute code, and collaborate with the community.


## Ways to Contribute

You can help in several ways:
- **Report issues**: Bug reports, feature requests, documentation fixes.
- **Improve documentation**: README, contract comments, usage guides.
- **Contribute code**: Fix bugs, improve contracts, add new features, optimize tooling.
- **Testing & feedback**: Run tests, verify deployments, and report issues with schemas or attestations.


## Testing & Quality Checks

- Test & Check coverage
  ```bash
  pnpm test:coverage
  ```

- Lint
  ```bash
  pnpm lint
  ```

- Static analysis (Slither)
  ```bash
  pnpm slither
  ```

Please make sure all checks pass before submitting a Pull Request.



## Git Workflow

We use a standard GitHub flow:

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-awesome-fix
   ```
3. Make your changes
4. Run tests, lint, and static analysis
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) style:
   - `feat: add new resolver contract`
   - `fix: correct attester registry logic`
   - `docs: update schema registry instructions`
6. Push to your fork and open a Pull Request (PR)



## Pull Request Guidelines

- Keep PRs small and focused.
- Update documentation if your changes affect usage.
- Link related issues (e.g., `Closes #42`).
- PRs must pass tests, lint, and static analysis before review.



## Code Style

- Follow [Solidity Style Guide](https://docs.soliditylang.org/en/v0.8.21/style-guide.html).
- Use NatSpec for contract functions and events.
- Run `pnpm lint` before committing.



## Reporting Issues

- Search existing issues before opening a new one.
- Provide clear steps to reproduce.
- Include logs, configs, or environment details if relevant.



## Community

- Please follow our [Code of Conduct](.github/CODE_OF_CONDUCT.md).
- Join the discussions on Discord (coming soon).
- Respectful collaboration is expected in all interactions.



## License

By contributing, you agree that your contributions will be licensed under the same license as the repository.
