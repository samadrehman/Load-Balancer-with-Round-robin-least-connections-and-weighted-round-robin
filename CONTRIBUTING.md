# Contributing Guidelines

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## Security

### Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities. Instead:

1. Email security issues privately to the maintainers
2. Include detailed information about the vulnerability
3. Allow time for the issue to be addressed before public disclosure

See [SECURITY.md](SECURITY.md) for more information.

### Security Best Practices

- **Never commit secrets, API keys, or passwords**
- Always use environment variables for sensitive data
- Test security features before submitting PRs
- Review security implications of your changes
- Follow secure coding practices

## Getting Started

1. Fork the repository
2. Clone your fork: 
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run in development mode
npm run dev

# Run tests (if available)
npm test
```

## Code Standards

### TypeScript

- Use TypeScript for all new code
- Follow existing code style
- Use meaningful variable and function names
- Add JSDoc comments for public functions
- Keep functions focused and small

### Code Style

- Use 2 spaces for indentation
- Use semicolons
- Use single quotes for strings
- Follow existing patterns in the codebase
- Use async/await instead of callbacks where possible

### Testing

- Add tests for new features
- Ensure all tests pass before submitting
- Test edge cases and error conditions
- Maintain or improve test coverage

## Pull Request Process

1. **Update Documentation**
   - Update README.md if needed
   - Add/update code comments
   - Update CHANGELOG.md if applicable

2. **Run Tests**
   ```bash
   npm test
   npm run build
   ```

3. **Check for Issues**
   - Run `npm audit` to check for vulnerabilities
   - Fix any linting errors
   - Ensure code compiles without errors

4. **Write Clear Commit Messages**
   - Use present tense ("Add feature" not "Added feature")
   - Be descriptive but concise
   - Reference issues if applicable

5. **Submit PR**
   - Provide clear description of changes
   - Reference related issues
   - Request review from maintainers

## What to Contribute

We welcome contributions in the following areas:

### Features

- New load balancing algorithms
- Additional monitoring/metrics
- Performance improvements
- New security features
- Documentation improvements

### Bug Fixes

- Fix reported bugs
- Improve error handling
- Fix security vulnerabilities
- Performance optimizations

### Documentation

- Improve README
- Add code examples
- Write tutorials
- Fix typos and errors

## Code Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged
4. Thank you for contributing!

## Questions?

If you have questions about contributing:

- Open a GitHub issue for general questions
- Check existing issues and PRs
- Review the documentation

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

