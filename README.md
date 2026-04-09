# AIrevtool

AIrevtool is a Windows-focused Electron application for AI-assisted reverse engineering and vulnerability triage. It combines a desktop UI, LM Studio for local inference, and an x64dbg plugin bridge to inspect live processes, review memory and disassembly, prioritize findings, generate safe PoC guidance, and export analyst reports.

The project is intended to help researchers and developers inspect binaries faster while keeping a human in the loop.
<img width="1729" height="940" alt="capture-1" src="https://github.com/user-attachments/assets/0ef9357d-4e7e-43ee-9bc9-e5f572acd864" />

## Current Release

- Version: `0.5.0`
- Platform: Windows 10/11 x64
- UI language: English
- Reports: Markdown and PDF

## What It Does

- Connects to x64dbg through the `AIrevPlugin` WebSocket bridge.
- Displays a live memory map, disassembly view, register state, debugger log, and breakpoints.
- Uses LM Studio to analyze memory regions and disassembly chunks.
- Classifies findings by severity, category, exploitability, and CWE.
- Generates a final report when analysis completes.
- Exports report artifacts to Markdown and PDF.
- Lets analysts add an optional custom prompt before each analysis run.

## Architecture

AIrevtool has three major parts:

1. Electron desktop application
2. Native x64dbg plugin (`AIrevPlugin.dp64`)
3. LM Studio local inference backend

Runtime flow:

1. x64dbg loads `AIrevPlugin`.
2. The plugin exposes a WebSocket server on `ws://127.0.0.1:27042`.
3. AIrevtool connects to that socket.
4. The app reads debugger state, memory, disassembly, and breakpoints.
5. LM Studio analyzes the collected context and generates findings and reports.

## Requirements

For correct operation, prepare the following:

- Windows 10 or Windows 11 x64
- Node.js 20 or newer
- npm 10 or newer
- LM Studio running locally with at least one chat model loaded
- An embedding model loaded in LM Studio for RAG-style context compression
- x64dbg x64
- Visual Studio 2022 or 2019 with MSBuild if you want to build the native plugin from source

Recommended LM Studio setup:

- Chat model: a capable instruction-tuned reasoning model
- Embedding model: a local embedding model compatible with LM Studio's embedding API

## End-User Installation

This repository is intended to be published as source code only.

There are currently no public binary releases and no installer distribution planned for GitHub. To use AIrevtool, clone the repository and build it locally.

Recommended local setup:

1. Clone this repository.
2. Clone x64dbg as a sibling folder.
3. Install and launch LM Studio.
4. Load your preferred analysis model and embedding model in LM Studio.
5. Build and deploy the `AIrevPlugin` plugin.
6. Start x64dbg before loading a target in AIrevtool if you want full live-debugger integration.
7. Run AIrevtool locally.

Notes:

- AIrevtool can still create a session if x64dbg is not connected, but the richest workflow depends on the plugin bridge being active.
- Report files are saved under `Documents/AIrevtool/Reports/<sessionId>/`.

## Developer Setup

Clone the project and keep the expected folder layout:

```text
ReverserTool/
  AIrevtool/
  x64dbg/
```

This layout matters because the plugin build and deploy script expects the x64dbg folder to be a sibling of the AIrevtool folder.

### 1. Install JavaScript dependencies

From the `AIrevtool` root:

```powershell
npm install
```

### 2. Prepare LM Studio

1. Start LM Studio.
2. Enable the local server / OpenAI-compatible API.
3. Load at least:
   - one chat model
   - one embedding model
4. Keep LM Studio running while using AIrevtool.

Default URL used by the app:

```text
http://localhost:12345
```

If your LM Studio server uses a different port, update it in the Settings panel.

### 3. Build and deploy the x64dbg plugin

From the `AIrevtool` root:

```powershell
npm run build:plugin
```

What this does:

- locates MSBuild
- builds `x64dbg-plugin/build/AIrevPlugin.sln`
- produces `AIrevPlugin.dp64`
- if `../x64dbg/bin/plugins/` exists, deploys it there automatically
- otherwise leaves the compiled plugin in `x64dbg-plugin/build/Release/AIrevPlugin.dp64` so you can copy it manually

### 4. Run the desktop app in development

```powershell
npm run dev:electron
```

### 4.1 Run the built app locally without packaging

```powershell
npm run start
```

This rebuilds the Electron main process and renderer, then launches the app from the local `dist` and `dist-electron` outputs.

### 5. Build a local packaged build

```powershell
npm run build
```

This builds:

- Electron main process
- renderer
- x64dbg plugin
- Windows installer via `electron-builder`

This step is optional if you only want to run the app in development mode.

## Correct Working Installation Checklist

For a fully working installation, validate all of the following:

1. LM Studio is running.
2. The configured base URL in AIrevtool matches the LM Studio local server.
3. A chat model is loaded in LM Studio.
4. An embedding model is loaded in LM Studio.
5. `AIrevPlugin.dp64` is present in the x64dbg `bin/plugins` directory.
6. x64dbg is started before you try to use live debugger integration.
7. The target binary can be opened by x64dbg.
8. The app Settings panel contains valid model names.

If any of these are missing, AIrevtool may still open, but memory/disassembly-backed analysis will be incomplete or unavailable.

## First Run Guide

1. Open AIrevtool.
2. Go to Settings.
<img width="1729" height="940" alt="capture-4" src="https://github.com/user-attachments/assets/a85ea882-9aef-4282-8282-8f56639441eb" />

3. Confirm the LM Studio URL.
4. Fetch available models.
5. Choose the analysis model and embedding model.
6. Save configuration.
7. Click Browse and select a target binary.
8. Click Load.
9. Start analysis.
<img width="1729" height="940" alt="capture-2" src="https://github.com/user-attachments/assets/dec3f33a-a0ff-4029-b793-9c78e72da2a2" />

10. Optionally provide a custom analysis prompt.
<img width="1600" height="900" alt="capture-6" src="https://github.com/user-attachments/assets/da1abd75-4826-4986-9acd-b6f69cd25d65" />

11. Review findings, PoC guidance, and the generated report.
<img width="1729" height="940" alt="capture-5" src="https://github.com/user-attachments/assets/d3993da3-0e09-4bac-a1d6-246e3d33624f" />


## Reports

When analysis completes, AIrevtool automatically generates a final report.

Report outputs:

- Markdown
- PDF

Saved location:

```text
Documents/AIrevtool/Reports/<sessionId>/
```

The Findings panel also exposes the generated report and a direct `Export .md` action.

## UI Overview

- Agents: agent progress, state, and logs
- Findings: vulnerability list, severity filters, PoC generation, report view
- Disasm: x64dbg-style disassembly grid
- Memory: x64dbg-style memory map
- Config: LM Studio configuration and project About section

## Safety Notes

AIrevtool is designed for defensive research, internal validation, and review workflows.

- PoC output is intentionally constrained to safe validation guidance.
- The application is not intended to generate weaponized exploit payloads.
- Always review AI output manually before acting on it.

## Acknowledgements

AIrevtool builds on top of the x64dbg ecosystem.

Many thanks to DREG and the x64dbg team for creating such an outstanding debugger and reverse engineering platform.

x64dbg remains its own project and keeps its own licensing and authorship.

## Credits

AIrevtool was created jointly by:

- Juan C. Montes: https://www.linkedin.com/in/juancmontes/
- Carlos Perez Gonzalez: https://www.linkedin.com/in/c-p-g

## License

This repository is released under the MIT License. See the `LICENSE` file for details.
