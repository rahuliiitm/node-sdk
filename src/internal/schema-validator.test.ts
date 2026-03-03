import { validateSchema, validateOutputSchema, type JsonSchema, type OutputSchemaOptions } from './schema-validator';

describe('validateSchema', () => {
  // ── Type validation ─────────────────────────────────────────────────────

  describe('type validation', () => {
    it('validates string type', () => {
      expect(validateSchema('hello', { type: 'string' })).toHaveLength(0);
      expect(validateSchema(42, { type: 'string' })).toHaveLength(1);
    });

    it('validates number type', () => {
      expect(validateSchema(42, { type: 'number' })).toHaveLength(0);
      expect(validateSchema(3.14, { type: 'number' })).toHaveLength(0);
      expect(validateSchema('42', { type: 'number' })).toHaveLength(1);
    });

    it('validates integer type', () => {
      expect(validateSchema(42, { type: 'integer' })).toHaveLength(0);
      expect(validateSchema(3.14, { type: 'integer' })).toHaveLength(1);
    });

    it('validates boolean type', () => {
      expect(validateSchema(true, { type: 'boolean' })).toHaveLength(0);
      expect(validateSchema('true', { type: 'boolean' })).toHaveLength(1);
    });

    it('validates array type', () => {
      expect(validateSchema([1, 2], { type: 'array' })).toHaveLength(0);
      expect(validateSchema('not array', { type: 'array' })).toHaveLength(1);
    });

    it('validates object type', () => {
      expect(validateSchema({ a: 1 }, { type: 'object' })).toHaveLength(0);
      expect(validateSchema([1], { type: 'object' })).toHaveLength(1);
    });

    it('validates null type', () => {
      expect(validateSchema(null, { type: 'null' })).toHaveLength(0);
      expect(validateSchema(undefined, { type: 'null' })).toHaveLength(1);
    });

    it('validates union types', () => {
      expect(validateSchema('hello', { type: ['string', 'null'] })).toHaveLength(0);
      expect(validateSchema(null, { type: ['string', 'null'] })).toHaveLength(0);
      expect(validateSchema(42, { type: ['string', 'null'] })).toHaveLength(1);
    });
  });

  // ── Required fields ─────────────────────────────────────────────────────

  describe('required fields', () => {
    it('reports missing required fields', () => {
      const schema: JsonSchema = {
        type: 'object',
        required: ['name', 'score'],
        properties: {
          name: { type: 'string' },
          score: { type: 'number' },
        },
      };
      const errors = validateSchema({ name: 'test' }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('/score');
      expect(errors[0].message).toContain('Missing required field');
    });

    it('passes when all required fields present', () => {
      const schema: JsonSchema = {
        type: 'object',
        required: ['name'],
        properties: { name: { type: 'string' } },
      };
      expect(validateSchema({ name: 'test' }, schema)).toHaveLength(0);
    });
  });

  // ── Nested object validation ────────────────────────────────────────────

  describe('nested objects', () => {
    it('validates nested property types', () => {
      const schema: JsonSchema = {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            required: ['id'],
            properties: {
              id: { type: 'integer' },
              name: { type: 'string' },
            },
          },
        },
      };
      const errors = validateSchema({ user: { name: 'test' } }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('/user/id');
    });
  });

  // ── Enum validation ─────────────────────────────────────────────────────

  describe('enum validation', () => {
    it('passes for valid enum value', () => {
      expect(validateSchema('red', { enum: ['red', 'green', 'blue'] })).toHaveLength(0);
    });

    it('fails for invalid enum value', () => {
      const errors = validateSchema('yellow', { enum: ['red', 'green', 'blue'] });
      expect(errors).toHaveLength(1);
      expect(errors[0].message).toContain('must be one of');
    });
  });

  // ── String constraints ──────────────────────────────────────────────────

  describe('string constraints', () => {
    it('validates minLength', () => {
      expect(validateSchema('ab', { type: 'string', minLength: 3 })).toHaveLength(1);
      expect(validateSchema('abc', { type: 'string', minLength: 3 })).toHaveLength(0);
    });

    it('validates maxLength', () => {
      expect(validateSchema('abcd', { type: 'string', maxLength: 3 })).toHaveLength(1);
      expect(validateSchema('abc', { type: 'string', maxLength: 3 })).toHaveLength(0);
    });

    it('validates pattern', () => {
      expect(validateSchema('abc123', { type: 'string', pattern: '^[a-z]+$' })).toHaveLength(1);
      expect(validateSchema('abc', { type: 'string', pattern: '^[a-z]+$' })).toHaveLength(0);
    });
  });

  // ── Number constraints ──────────────────────────────────────────────────

  describe('number constraints', () => {
    it('validates minimum', () => {
      expect(validateSchema(5, { type: 'number', minimum: 10 })).toHaveLength(1);
      expect(validateSchema(10, { type: 'number', minimum: 10 })).toHaveLength(0);
    });

    it('validates maximum', () => {
      expect(validateSchema(15, { type: 'number', maximum: 10 })).toHaveLength(1);
      expect(validateSchema(10, { type: 'number', maximum: 10 })).toHaveLength(0);
    });
  });

  // ── Array validation ────────────────────────────────────────────────────

  describe('array validation', () => {
    it('validates items schema', () => {
      const schema: JsonSchema = {
        type: 'array',
        items: { type: 'string' },
      };
      expect(validateSchema(['a', 'b'], schema)).toHaveLength(0);
      expect(validateSchema(['a', 42], schema)).toHaveLength(1);
    });

    it('validates minItems', () => {
      expect(validateSchema([], { type: 'array', minItems: 1 })).toHaveLength(1);
      expect(validateSchema([1], { type: 'array', minItems: 1 })).toHaveLength(0);
    });

    it('validates maxItems', () => {
      expect(validateSchema([1, 2, 3], { type: 'array', maxItems: 2 })).toHaveLength(1);
      expect(validateSchema([1, 2], { type: 'array', maxItems: 2 })).toHaveLength(0);
    });
  });

  // ── Additional properties ───────────────────────────────────────────────

  describe('additionalProperties', () => {
    it('blocks extra properties when false', () => {
      const schema: JsonSchema = {
        type: 'object',
        properties: { name: { type: 'string' } },
        additionalProperties: false,
      };
      expect(validateSchema({ name: 'test', extra: 1 }, schema)).toHaveLength(1);
      expect(validateSchema({ name: 'test' }, schema)).toHaveLength(0);
    });
  });

  // ── Combinators ─────────────────────────────────────────────────────────

  describe('combinators', () => {
    it('validates anyOf', () => {
      const schema: JsonSchema = {
        anyOf: [{ type: 'string' }, { type: 'number' }],
      };
      expect(validateSchema('hello', schema)).toHaveLength(0);
      expect(validateSchema(42, schema)).toHaveLength(0);
      expect(validateSchema(true, schema)).toHaveLength(1);
    });

    it('validates allOf', () => {
      const schema: JsonSchema = {
        allOf: [
          { type: 'object', required: ['name'] },
          { type: 'object', required: ['score'] },
        ],
      };
      expect(validateSchema({ name: 'a', score: 1 }, schema)).toHaveLength(0);
      expect(validateSchema({ name: 'a' }, schema)).toHaveLength(1);
    });
  });
});

describe('validateOutputSchema', () => {
  it('validates valid JSON response', () => {
    const options: OutputSchemaOptions = {
      schema: {
        type: 'object',
        required: ['name', 'score'],
        properties: {
          name: { type: 'string' },
          score: { type: 'number', minimum: 0, maximum: 100 },
        },
      },
    };
    const result = validateOutputSchema('{"name": "test", "score": 85}', options);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.parsed).toEqual({ name: 'test', score: 85 });
  });

  it('reports invalid JSON', () => {
    const result = validateOutputSchema('not json at all', { schema: { type: 'object' } });
    expect(result.valid).toBe(false);
    expect(result.errors[0].message).toContain('Invalid JSON');
  });

  it('reports schema violations', () => {
    const options: OutputSchemaOptions = {
      schema: {
        type: 'object',
        required: ['name', 'score'],
        properties: {
          name: { type: 'string' },
          score: { type: 'number' },
        },
      },
    };
    const result = validateOutputSchema('{"name": "test"}', options);
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
  });

  it('calls onInvalid callback on failure', () => {
    const errors: any[] = [];
    const options: OutputSchemaOptions = {
      schema: { type: 'object', required: ['id'] },
      onInvalid: (e) => errors.push(...e),
    };
    validateOutputSchema('{}', options);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('does not call onInvalid on success', () => {
    let called = false;
    const options: OutputSchemaOptions = {
      schema: { type: 'object' },
      onInvalid: () => { called = true; },
    };
    validateOutputSchema('{}', options);
    expect(called).toBe(false);
  });
});
