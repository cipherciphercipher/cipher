import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
    { ignores: ["node_modules/", ".vencord/", "coverage/"] },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        languageOptions: {
            globals: { crypto: "readonly", TextEncoder: "readonly", TextDecoder: "readonly", console: "readonly", process: "readonly" }
        },
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
            // Plaintext and keys must never reach a console.
            "no-console": "error",
            "eqeqeq": ["error", "smart"],
            "prefer-const": "error"
        }
    },
    {
        files: ["scripts/**"],
        rules: { "no-console": "off" }
    }
);
