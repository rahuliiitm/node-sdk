/**
 * Zero-dependency JSON schema validator (draft-07 subset).
 * Validates LLM output against a user-provided schema.
 * @internal
 */

export interface SchemaValidationError {
  /** JSON pointer path to the invalid value (e.g., "/name", "/items/0/score"). */
  path: string;
  /** Human-readable error message. */
  message: string;
  /** The expected constraint. */
  expected?: string;
  /** The actual value that failed validation. */
  actual?: unknown;
}

export interface OutputSchemaOptions {
  /** The JSON schema to validate against. */
  schema: JsonSchema;
  /** Throw SchemaValidationError if validation fails. Default: false. */
  blockOnInvalid?: boolean;
  /** Called when validation fails. */
  onInvalid?: (errors: SchemaValidationError[]) => void;
}

export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minItems?: number;
  maxItems?: number;
  additionalProperties?: boolean | JsonSchema;
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  allOf?: JsonSchema[];
  const?: unknown;
  not?: JsonSchema;
  /** Allow any value. */
  [key: string]: unknown;
}

/**
 * Validate a value against a JSON schema.
 * Returns an array of validation errors (empty = valid).
 */
export function validateSchema(value: unknown, schema: JsonSchema, path = ''): SchemaValidationError[] {
  const errors: SchemaValidationError[] = [];

  // Type validation
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actualType = getJsonType(value);
    // In JSON Schema, "number" accepts both integers and floats
    const typeMatches = types.includes(actualType)
      || (actualType === 'integer' && types.includes('number'));
    if (!typeMatches) {
      errors.push({
        path: path || '/',
        message: `Expected type ${types.join(' | ')}, got ${actualType}`,
        expected: types.join(' | '),
        actual: actualType,
      });
      return errors; // Type mismatch — skip further validation
    }
  }

  // Const validation
  if (schema.const !== undefined) {
    if (!deepEqual(value, schema.const)) {
      errors.push({
        path: path || '/',
        message: `Expected constant ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`,
        expected: JSON.stringify(schema.const),
        actual: value,
      });
    }
  }

  // Enum validation
  if (schema.enum !== undefined) {
    if (!schema.enum.some((e) => deepEqual(e, value))) {
      errors.push({
        path: path || '/',
        message: `Value must be one of: ${schema.enum.map((e) => JSON.stringify(e)).join(', ')}`,
        expected: schema.enum.map((e) => JSON.stringify(e)).join(' | '),
        actual: value,
      });
    }
  }

  // String validations
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push({
        path: path || '/',
        message: `String length ${value.length} is less than minimum ${schema.minLength}`,
        expected: `minLength: ${schema.minLength}`,
        actual: value.length,
      });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push({
        path: path || '/',
        message: `String length ${value.length} exceeds maximum ${schema.maxLength}`,
        expected: `maxLength: ${schema.maxLength}`,
        actual: value.length,
      });
    }
    if (schema.pattern !== undefined) {
      try {
        const regex = new RegExp(schema.pattern);
        if (!regex.test(value)) {
          errors.push({
            path: path || '/',
            message: `String does not match pattern: ${schema.pattern}`,
            expected: `pattern: ${schema.pattern}`,
            actual: value,
          });
        }
      } catch {
        // Invalid regex in schema — skip
      }
    }
  }

  // Number validations
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push({
        path: path || '/',
        message: `Value ${value} is less than minimum ${schema.minimum}`,
        expected: `minimum: ${schema.minimum}`,
        actual: value,
      });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push({
        path: path || '/',
        message: `Value ${value} exceeds maximum ${schema.maximum}`,
        expected: `maximum: ${schema.maximum}`,
        actual: value,
      });
    }
  }

  // Object validations
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;

    // Required fields
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in obj)) {
          errors.push({
            path: `${path}/${key}`,
            message: `Missing required field: ${key}`,
            expected: 'required',
          });
        }
      }
    }

    // Properties
    if (schema.properties) {
      for (const [key, propSchema] of Object.entries(schema.properties)) {
        if (key in obj) {
          errors.push(...validateSchema(obj[key], propSchema, `${path}/${key}`));
        }
      }
    }

    // Additional properties
    if (schema.additionalProperties !== undefined && schema.properties) {
      const allowedKeys = new Set(Object.keys(schema.properties));
      for (const key of Object.keys(obj)) {
        if (!allowedKeys.has(key)) {
          if (schema.additionalProperties === false) {
            errors.push({
              path: `${path}/${key}`,
              message: `Additional property not allowed: ${key}`,
            });
          } else if (typeof schema.additionalProperties === 'object') {
            errors.push(...validateSchema(obj[key], schema.additionalProperties, `${path}/${key}`));
          }
        }
      }
    }
  }

  // Array validations
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push({
        path: path || '/',
        message: `Array length ${value.length} is less than minimum ${schema.minItems}`,
        expected: `minItems: ${schema.minItems}`,
        actual: value.length,
      });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push({
        path: path || '/',
        message: `Array length ${value.length} exceeds maximum ${schema.maxItems}`,
        expected: `maxItems: ${schema.maxItems}`,
        actual: value.length,
      });
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        errors.push(...validateSchema(value[i], schema.items, `${path}/${i}`));
      }
    }
  }

  // Combinators
  if (schema.allOf) {
    for (const sub of schema.allOf) {
      errors.push(...validateSchema(value, sub, path));
    }
  }
  if (schema.anyOf) {
    const anyValid = schema.anyOf.some((sub) => validateSchema(value, sub, path).length === 0);
    if (!anyValid) {
      errors.push({
        path: path || '/',
        message: `Value does not match any of the anyOf schemas`,
      });
    }
  }
  if (schema.oneOf) {
    const matching = schema.oneOf.filter((sub) => validateSchema(value, sub, path).length === 0);
    if (matching.length !== 1) {
      errors.push({
        path: path || '/',
        message: matching.length === 0
          ? `Value does not match any oneOf schema`
          : `Value matches ${matching.length} oneOf schemas (expected exactly 1)`,
      });
    }
  }
  if (schema.not) {
    if (validateSchema(value, schema.not, path).length === 0) {
      errors.push({
        path: path || '/',
        message: `Value should not match the "not" schema`,
      });
    }
  }

  return errors;
}

/**
 * Validate an LLM response string as JSON against a schema.
 * First parses the JSON, then validates.
 */
export function validateOutputSchema(
  responseText: string,
  options: OutputSchemaOptions,
): { valid: boolean; errors: SchemaValidationError[]; parsed?: unknown } {
  // Try to parse JSON (with fallback for markdown-fenced JSON)
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    // Try extracting JSON from markdown code fences (```json ... ```)
    const fenceMatch = responseText.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
    if (fenceMatch) {
      try {
        parsed = JSON.parse(fenceMatch[1].trim());
      } catch (e2) {
        const errors: SchemaValidationError[] = [{
          path: '/',
          message: `Invalid JSON: ${(e2 as Error).message}`,
        }];
        if (options.onInvalid) { options.onInvalid(errors); }
        return { valid: false, errors };
      }
    } else {
      const errors: SchemaValidationError[] = [{
        path: '/',
        message: 'Invalid JSON: response is not valid JSON and contains no markdown code fence',
      }];
      if (options.onInvalid) { options.onInvalid(errors); }
      return { valid: false, errors };
    }
  }

  const errors = validateSchema(parsed, options.schema);

  if (errors.length > 0 && options.onInvalid) {
    options.onInvalid(errors);
  }

  return { valid: errors.length === 0, errors, parsed };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getJsonType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') {
    return Number.isInteger(value) ? 'integer' : 'number';
  }
  return typeof value; // string, boolean, object
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }

  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj);
  const bKeys = Object.keys(bObj);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((key) => deepEqual(aObj[key], bObj[key]));
}
