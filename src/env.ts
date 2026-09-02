/**
 * Reading the API key, in one place.
 *
 * Returning the value (rather than guarding a module-level const) keeps the
 * type as `string` at every use site — TypeScript does not carry a narrowing
 * from module scope into a later function body.
 */
export function requireApiKey(): string {
  const key = process.env.SOLARI_API_KEY
  if (!key) {
    process.stderr.write(
      "SOLARI_API_KEY is not set.\n" + "Load it from the project .env with:  set -a && . ./.env && set +a\n",
    )
    process.exit(1)
  }
  return key
}
