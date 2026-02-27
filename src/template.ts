const VARIABLE_PATTERN = /\{\{(\w+)\}\}/g;

/**
 * Extract unique variable names from a prompt template.
 * Matches `{{variableName}}` patterns.
 */
export function extractVariables(template: string): string[] {
  const vars = new Set<string>();
  let match;
  while ((match = VARIABLE_PATTERN.exec(template)) !== null) {
    vars.add(match[1]!);
  }
  return [...vars];
}

/**
 * Replace `{{variable}}` placeholders with values from the provided map.
 * Unmatched variables are left as-is.
 */
export function interpolate(
  template: string,
  variables: Record<string, string>,
): string {
  return template.replace(VARIABLE_PATTERN, (match: string, name: string) => {
    return name in variables ? variables[name]! : match;
  });
}
