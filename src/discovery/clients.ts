/**
 * Where MCP client configuration lives.
 *
 * Discovery is entirely passive: it reads files and connects to nothing. An
 * inventory of a machine should never be the thing that wakes up a server.
 *
 * ## Confidence
 *
 * Each entry records how well the path is confirmed. `confirmed` means it was
 * verified against vendor documentation. `probable` means it is the widely used
 * location but was not confirmed, and it is listed in `VERIFY.md` section 1 for
 * somebody who runs that client to check. Nothing here is asserted as fact that was not
 * actually checked, because a discovery tool that invents paths reports a clean
 * machine when the truth is that it looked in the wrong place.
 */

import { homedir, platform } from 'node:os';
import { join } from 'node:path';

export type ClientId =
  | 'claude-desktop'
  | 'claude-code'
  | 'cursor'
  | 'vscode'
  | 'windsurf'
  | 'cline'
  | 'zed'
  | 'generic';

export type PathConfidence = 'confirmed' | 'probable';

/**
 * How a client's file nests its server map.
 *
 * `mcpServers` is by far the most common, having been established by Claude
 * Desktop and adopted by Claude Code and Cursor. The others differ, which is why
 * a parser cannot simply look for one key.
 */
export type ConfigShape = 'mcpServers' | 'servers' | 'context_servers';

export interface ClientDefinition {
  readonly id: ClientId;
  readonly displayName: string;
  readonly shape: ConfigShape;
  readonly confidence: PathConfidence;
  /** Absolute candidate paths on the current platform, most likely first. */
  readonly paths: readonly string[];
  /** Note recorded in the inventory when the path is not confirmed. */
  readonly note?: string;
}

function windowsAppData(): string {
  return process.env['APPDATA'] ?? join(homedir(), 'AppData', 'Roaming');
}

/**
 * Every known configuration location for the current platform.
 *
 * Paths are absolute. Nothing is read here; existence is checked by the scanner.
 */
export function knownClients(): readonly ClientDefinition[] {
  const home = homedir();
  const os = platform();

  const claudeDesktop =
    os === 'win32'
      ? [join(windowsAppData(), 'Claude', 'claude_desktop_config.json')]
      : os === 'darwin'
        ? [join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')]
        : [join(home, '.config', 'claude-desktop', 'claude_desktop_config.json')];

  const windsurf =
    os === 'win32'
      ? [join(home, '.codeium', 'windsurf', 'mcp_config.json')]
      : [join(home, '.codeium', 'windsurf', 'mcp_config.json')];

  const vscodeUserDir =
    os === 'win32'
      ? join(windowsAppData(), 'Code', 'User')
      : os === 'darwin'
        ? join(home, 'Library', 'Application Support', 'Code', 'User')
        : join(home, '.config', 'Code', 'User');

  const clineLegacyDir =
    os === 'win32'
      ? join(windowsAppData(), 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings')
      : os === 'darwin'
        ? join(
            home,
            'Library',
            'Application Support',
            'Code',
            'User',
            'globalStorage',
            'saoudrizwan.claude-dev',
            'settings',
          )
        : join(home, '.config', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings');

  // As of Cline 4.x, MCP settings moved out of the VS Code extension's
  // globalStorage into a shared, editor-independent data directory. The
  // legacy globalStorage file is read once on first launch to migrate, then
  // Cline stops writing to it -- so it is a stale read on any current
  // install and must be checked second, not first.
  const clineCurrentDir = join(home, '.cline', 'data', 'settings');

  return [
    {
      id: 'claude-desktop',
      displayName: 'Claude Desktop',
      shape: 'mcpServers',
      confidence: 'confirmed',
      paths: claudeDesktop,
    },
    {
      id: 'claude-code',
      displayName: 'Claude Code',
      shape: 'mcpServers',
      confidence: 'confirmed',
      paths: [join(home, '.claude.json')],
    },
    {
      id: 'cursor',
      displayName: 'Cursor',
      shape: 'mcpServers',
      confidence: 'confirmed',
      paths: [join(home, '.cursor', 'mcp.json')],
    },
    {
      id: 'vscode',
      displayName: 'VS Code',
      // Confirmed empirically: a real discover run located servers at this path
      // and parsed them with the `servers` shape. The workspace variant below
      // stays `probable`, because it has not been checked the same way.
      shape: 'servers',
      confidence: 'confirmed',
      paths: [join(vscodeUserDir, 'mcp.json')],
      note: 'VS Code also supports a workspace .vscode/mcp.json, which a machine wide scan cannot enumerate without walking every project directory.',
    },
    {
      id: 'windsurf',
      displayName: 'Windsurf',
      shape: 'mcpServers',
      confidence: 'confirmed',
      paths: windsurf,
      note: 'Confirmed against Windsurf\'s own Cascade MCP integration docs (docs.windsurf.com/windsurf/cascade/mcp). The file is not created by Windsurf on first launch; its absence just means no MCP servers have been added yet, not that discovery failed.',
    },
    {
      id: 'cline',
      displayName: 'Cline',
      shape: 'mcpServers',
      confidence: 'confirmed',
      // Current path first: Cline 4.x moved MCP settings to a shared,
      // editor-independent data directory. Legacy globalStorage path kept as
      // a fallback for installs that have not migrated (Cline reads it once
      // on first launch to migrate, then stops writing to it).
      paths: [join(clineCurrentDir, 'cline_mcp_settings.json'), join(clineLegacyDir, 'cline_mcp_settings.json')],
      note: 'Confirmed against Cline\'s own documentation and cline/cline GitHub issues discussing the 4.x migration off VS Code extension globalStorage. Both the current and legacy paths are checked since installs may not have migrated yet.',
    },
    {
      id: 'zed',
      displayName: 'Zed',
      shape: 'context_servers',
      confidence: 'confirmed',
      paths:
        os === 'win32'
          ? [join(windowsAppData(), 'Zed', 'settings.json')]
          : [join(home, '.config', 'zed', 'settings.json')],
      note: 'Confirmed against Zed\'s own docs (zed-industries/zed, docs/src/configuring-zed.md): macOS and Linux both use ~/.config/zed/settings.json, but Windows uses %APPDATA%\\Zed\\settings.json, a different path with different capitalization -- the code previously used the Linux/macOS path unconditionally on every platform, which would have silently missed every Windows Zed install. Zed nests servers under context_servers inside this general settings file rather than a dedicated MCP file.',
    },
  ];
}

/**
 * A generic `mcp.json` in a directory, for project local configuration.
 *
 * Separate from {@link knownClients} because it is relative to a directory the
 * caller names rather than to the home directory.
 */
export function projectConfigCandidates(directory: string): readonly ClientDefinition[] {
  return [
    {
      id: 'generic',
      displayName: 'Project mcp.json',
      shape: 'mcpServers',
      confidence: 'probable',
      paths: [join(directory, 'mcp.json'), join(directory, '.mcp.json')],
      note: 'A convention rather than a specification. Shape is assumed to match the common mcpServers form.',
    },
    {
      id: 'vscode',
      displayName: 'VS Code workspace',
      shape: 'servers',
      confidence: 'probable',
      paths: [join(directory, '.vscode', 'mcp.json')],
    },
    {
      id: 'cursor',
      displayName: 'Cursor workspace',
      shape: 'mcpServers',
      confidence: 'probable',
      paths: [join(directory, '.cursor', 'mcp.json')],
    },
  ];
}
