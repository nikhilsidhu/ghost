// Theme values resolved for canvas drawing, which cannot read CSS variables; each is
// looked up once, as the theme does not change while the window is open.

const cache = new Map<string, string>();

export function themeValue(variable: string): string {
  let value = cache.get(variable);
  if (value === undefined) {
    value = getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
    cache.set(variable, value);
  }
  return value;
}

export const shade = (family: string, level: number) => themeValue(`--${family}-${level}`);
