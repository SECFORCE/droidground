# 📚 Frida Script Library

This folder contains a curated set of **jailed Frida scripts** used within the _DroidGround_ platform. These scripts provide limited, safe dynamic instrumentation capabilities to challenge participants without granting them full control over the Frida runtime.

## 🔒 Why Jailed Frida?

Frida is an incredibly powerful dynamic instrumentation toolkit, but this power also makes it risky in a competitive or educational environment. Unrestricted Frida access can lead to:

- **Challenge bypassing** by directly reading memory or intercepting flag values
- **Sandbox escape attempts** or tampering with the platform
- **Unintended crashes** due to poorly written or malicious scripts

To address this, we designed a **jailed Frida mode** that:

- Offers predefined, **challenge-author-approved scripts**
- Allows users to **run scripts with controlled arguments**
- Prevents abuse while still enabling deep learning and interactivity

## 🧩 Script Structure & Convention

All Frida scripts in this folder must follow a common interface to be compatible with the platform.

### 📁 File Placement

- Place your script in this folder: `library/`
- Add an entry in `library.json` to register it (see below)

### 🔁 Required Exports

Each script must export exactly two functions using Frida’s RPC interface:

```javascript
rpc.exports = {
  run(args) {
    // Your script logic here
  },

  schema() {
    return {
      type: "object",
      properties: {
        // Define expected args here
      },
      required: [
        /* required arg names */
      ],
      additionalProperties: false,
    };
  },
};
```

- **`run`**: The `run` function must only allow one argument (use `args` as convention) which should be an _Object_ containing all the required fields.
- **`schema`**: The `schema` function should either return `null` (if no arguments are needed) or the _JSON schema_ (`ajv` format) that matches the expected args.

## 📚 `library.json` Format

This file indexes all scripts in the library so the platform can present them in the UI.

```json
[
  {
    "filename": "enumClasses.js",
    "description": "Enumerate all Java classes"
  },
  {
    "filename": "enumMethods.js",
    "description": "Enumerate all methods declared in a Java class"
  }
]
```

⚠️ Ensure each entry is kept in sync with the corresponding script file.

## ✅ Contribution Checklist

When adding a new script:

- Save your script to the `library/` folder.
- Export `run(args)` and `schema()`.
- Add an entry to `ibrary.json` with a clear description.
- Test your script on a sample app to verify it runs and validates correctly.
