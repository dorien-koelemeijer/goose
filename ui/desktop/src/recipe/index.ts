// TODO: These API functions don't exist yet
// import {
//   createRecipe as apiCreateRecipe,
//   encodeRecipe as apiEncodeRecipe,
//   decodeRecipe as apiDecodeRecipe,
// } from '../api';
// import type {
//   CreateRecipeRequest as ApiCreateRecipeRequest,
//   CreateRecipeResponse as ApiCreateRecipeResponse,
//   RecipeParameter,
//   Message as ApiMessage,
//   Role,
//   MessageContent,
// } from '../api';
import type { Message as FrontendMessage } from '../types/message';

// TODO: Define SubRecipe type when API is available
export interface SubRecipe {
  name?: string;
  path?: string;
  description?: string;
  values?: Record<string, string>;
}

// TODO: These types should come from the API when available
export interface RecipeParameter {
  key: string;
  description?: string;
  input_type?: string;
  requirement?: 'required' | 'optional' | 'user_prompt';
  default?: string;
  options?: string[];
}

export interface Recipe {
  title?: string;
  description?: string;
  instructions?: string;
  activities?: string[];
  prompt?: string;
  version?: string;
  parameters?: RecipeParameter[];
  extensions?: Array<{
    name: string;
    description?: string;
    [key: string]: unknown;
  }>;
  sub_recipes?: SubRecipe[];
  response?: {
    json_schema?: unknown;
  };
  context?: string[];
  author?: {
    contact?: string;
    metadata?: string;
  };
  // Properties added for scheduled execution
  scheduledJobId?: string;
  isScheduledExecution?: boolean;
  // Legacy frontend properties (not in OpenAPI schema)
  profile?: string;
  goosehints?: string;
  mcps?: number;
}

// Re-export types
export type Parameter = RecipeParameter;

// Create frontend-compatible type that accepts frontend Message until we can refactor.
export interface CreateRecipeRequest {
  // TODO: Fix this type to match Message OpenAPI spec
  messages: FrontendMessage[];
  title: string;
  description: string;
  activities?: string[];
  author?: {
    contact?: string;
    metadata?: string;
  };
}

export interface CreateRecipeResponse {
  recipe?: Recipe;
  error?: string;
}

// TODO: Implement these functions when API is available
export async function createRecipe(request: CreateRecipeRequest): Promise<CreateRecipeResponse> {
  console.log('Creating recipe with request:', JSON.stringify(request, null, 2));

  // Placeholder implementation
  return {
    error: 'Recipe API not implemented yet',
  };
}

export async function encodeRecipe(recipe: Recipe): Promise<string> {
  console.log('Encoding recipe:', recipe);

  // Placeholder implementation
  throw new Error('Recipe encoding API not implemented yet');
}

export async function decodeRecipe(deeplink: string): Promise<Recipe> {
  console.log('Decoding recipe from deeplink:', deeplink);

  // Placeholder implementation
  throw new Error('Recipe decoding API not implemented yet');
}

export async function generateDeepLink(recipe: Recipe): Promise<string> {
  const encoded = await encodeRecipe(recipe);
  return `goose://recipe?config=${encoded}`;
}
