import { spawn } from 'child_process';
import path from 'path';
import os from 'os';

const cargoBin = path.join(os.homedir(), '.cargo', 'bin');
const env = { ...process.env };

if (process.platform === 'win32') {
  env.PATH = `${cargoBin};${env.PATH || ''}`;
} else {
  env.PATH = `${cargoBin}:${env.PATH || ''}`;
}

// Find package manager or run tauri CLI
const isWin = process.platform === 'win32';
const cmd = isWin ? 'pnpm.cmd' : 'pnpm';

const child = spawn(cmd, ['tauri', 'dev'], {
  stdio: 'inherit',
  env,
  shell: true,
});

child.on('exit', (code) => {
  process.exit(code ?? 0);
});
