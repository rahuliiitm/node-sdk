import { extractVariables, interpolate } from './template';

describe('extractVariables', () => {
  it('should extract variable names from template', () => {
    expect(extractVariables('Hello {{name}}')).toEqual(['name']);
  });

  it('should deduplicate', () => {
    expect(extractVariables('{{x}} and {{x}}')).toEqual(['x']);
  });

  it('should return empty for no variables', () => {
    expect(extractVariables('plain text')).toEqual([]);
  });
});

describe('interpolate', () => {
  it('should replace variables with values', () => {
    const result = interpolate('Hello {{name}}, welcome to {{company}}!', {
      name: 'Alice',
      company: 'Acme',
    });
    expect(result).toBe('Hello Alice, welcome to Acme!');
  });

  it('should leave unmatched variables as-is', () => {
    const result = interpolate('Hello {{name}}, your role is {{role}}', {
      name: 'Bob',
    });
    expect(result).toBe('Hello Bob, your role is {{role}}');
  });

  it('should handle empty variables object', () => {
    const result = interpolate('Hello {{name}}', {});
    expect(result).toBe('Hello {{name}}');
  });

  it('should handle template with no variables', () => {
    const result = interpolate('No variables here', { name: 'unused' });
    expect(result).toBe('No variables here');
  });

  it('should handle multiline templates', () => {
    const template = `You are a {{role}}.
Help the user with {{topic}}.`;
    const result = interpolate(template, { role: 'teacher', topic: 'math' });
    expect(result).toBe(`You are a teacher.
Help the user with math.`);
  });

  it('should handle empty string values', () => {
    const result = interpolate('Hello {{name}}!', { name: '' });
    expect(result).toBe('Hello !');
  });

  it('should handle values with special regex characters', () => {
    const result = interpolate('Pattern: {{regex}}', { regex: '$1.00 (USD)' });
    expect(result).toBe('Pattern: $1.00 (USD)');
  });

  it('should handle adjacent variables', () => {
    const result = interpolate('{{first}}{{last}}', { first: 'John', last: 'Doe' });
    expect(result).toBe('JohnDoe');
  });

  it('should replace all occurrences of the same variable', () => {
    const result = interpolate('{{name}} said hi. {{name}} is here.', { name: 'Alice' });
    expect(result).toBe('Alice said hi. Alice is here.');
  });
});
