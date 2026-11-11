import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  Tool,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

let supabase: SupabaseClient | null = null;
if (supabaseUrl && supabaseKey) {
  try {
    supabase = createClient(supabaseUrl, supabaseKey);
  } catch (err) {
    console.error("Failed to initialize Supabase client:", err);
  }
}

const server = new Server(
  {
    name: "omnimcp-supabase-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const tools: Tool[] = [
  {
    name: "supabase_list_tables",
    description: "Inspect accessible tables, schema definitions, and views in the Supabase PostgreSQL database.",
    inputSchema: {
      type: "object",
      properties: {
        schema: { type: "string", description: "Database schema to inspect (default: 'public')" },
      },
    },
  },
  {
    name: "supabase_query_table",
    description: "Query rows from a Supabase database table with column selections, filtering, ordering, and pagination.",
    inputSchema: {
      type: "object",
      properties: {
        table: { type: "string", description: "Name of the database table" },
        columns: { type: "string", description: "Comma-separated columns to select (default: '*')" },
        match: { type: "object", description: "Key-value equality filter conditions", additionalProperties: true },
        limit: { type: "number", description: "Maximum number of rows to retrieve (default: 50)" },
      },
      required: ["table"],
    },
  },
  {
    name: "supabase_insert_record",
    description: "Insert one or more records into a Supabase database table.",
    inputSchema: {
      type: "object",
      properties: {
        table: { type: "string", description: "Target table name" },
        record: { type: "object", description: "Row data object or array of objects to insert", additionalProperties: true },
      },
      required: ["table", "record"],
    },
  },
  {
    name: "supabase_update_record",
    description: "Update existing records in a Supabase table matching specific conditions.",
    inputSchema: {
      type: "object",
      properties: {
        table: { type: "string", description: "Target table name" },
        values: { type: "object", description: "Columns to update", additionalProperties: true },
        match: { type: "object", description: "Filter condition for rows to update", additionalProperties: true },
      },
      required: ["table", "values", "match"],
    },
  },
  {
    name: "supabase_delete_record",
    description: "Delete records from a Supabase database table matching filter criteria.",
    inputSchema: {
      type: "object",
      properties: {
        table: { type: "string", description: "Target table name" },
        match: { type: "object", description: "Filter criteria for rows to delete", additionalProperties: true },
      },
      required: ["table", "match"],
    },
  },
  {
    name: "supabase_execute_rpc",
    description: "Call a PostgreSQL Database Function / Stored Procedure (RPC) via Supabase.",
    inputSchema: {
      type: "object",
      properties: {
        function_name: { type: "string", description: "Name of the Postgres function to execute" },
        arguments: { type: "object", description: "Arguments dictionary for the function", additionalProperties: true },
      },
      required: ["function_name"],
    },
  },
  {
    name: "supabase_list_users",
    description: "Query registered authentication users (requires SUPABASE_SERVICE_ROLE_KEY).",
    inputSchema: {
      type: "object",
      properties: {
        page: { type: "number", description: "Page number (default: 1)" },
        per_page: { type: "number", description: "Results per page (default: 20)" },
      },
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: rawArgs } = request.params;
  const args = (rawArgs || {}) as Record<string, any>;

  if (!supabase) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "unconfigured",
            message:
              "Supabase integration is registered but credentials are not yet configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file to enable live database queries.",
          }),
        },
      ],
    };
  }

  try {
    switch (name) {
      case "supabase_list_tables": {
        const schema = args.schema || "public";
        // Query information_schema via RPC or query
        const { data, error } = await supabase.rpc("get_schema_tables", { target_schema: schema });
        if (error) {
          // Fallback message if RPC helper isn't installed
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  message: "Direct schema reflection requires a helper RPC or standard PostgREST table querying.",
                  schema,
                  error: error.message,
                }),
              },
            ],
          };
        }
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_query_table": {
        let query = supabase.from(args.table).select(args.columns || "*");
        if (args.match && typeof args.match === "object") {
          query = query.match(args.match);
        }
        if (args.limit) {
          query = query.limit(Number(args.limit));
        } else {
          query = query.limit(50);
        }
        const { data, error } = await query;
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_insert_record": {
        const { data, error } = await supabase.from(args.table).insert(args.record).select();
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_update_record": {
        let query = supabase.from(args.table).update(args.values);
        if (args.match && typeof args.match === "object") {
          query = query.match(args.match);
        }
        const { data, error } = await query.select();
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_delete_record": {
        let query = supabase.from(args.table).delete();
        if (args.match && typeof args.match === "object") {
          query = query.match(args.match);
        }
        const { data, error } = await query.select();
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_execute_rpc": {
        const { data, error } = await supabase.rpc(args.function_name, args.arguments || {});
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "supabase_list_users": {
        const { data, error } = await supabase.auth.admin.listUsers({
          page: args.page || 1,
          perPage: args.per_page || 20,
        });
        if (error) throw new McpError(ErrorCode.InternalError, error.message);
        return { content: [{ type: "text", text: JSON.stringify(data.users, null, 2) }] };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown Supabase tool: ${name}`);
    }
  } catch (err: any) {
    if (err instanceof McpError) throw err;
    throw new McpError(ErrorCode.InternalError, err.message || String(err));
  }
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

run().catch((err) => {
  console.error("Fatal error starting Supabase MCP Server:", err);
  process.exit(1);
});

