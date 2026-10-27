export default {
  extends: ['@commitlint/config-conventional'],
  // Dependabot's header is conventional (see .github/dependabot.yml), but its body quotes release notes with lines over 100.
  ignores: [(message) => message.includes('Signed-off-by: dependabot[bot]')],
};
