/**
 * OTORI Dashboard - Utility Functions
 */

// Color constants
const COLORS = {
  accent: '#ff4fd8',
  blue: '#4cc9ff',
  green: '#34d399',
  red: '#f87171',
  yellow: '#fbbf24',
  orange: '#fb923c',
  purple: '#a78bfa',
  muted: '#8b95a5'
};

const CATEGORY_COLORS = {
  recon: COLORS.blue,
  download: COLORS.orange,
  persist: COLORS.red,
  credential: COLORS.purple,
  execution: COLORS.yellow,
  exfil: COLORS.accent,
  evasion: COLORS.muted,
  lateral: COLORS.green,
  impact: '#ef4444',
  benign: '#6b7280',
  unknown: '#4b5563'
};

const SEVERITY_COLORS = {
  critical: COLORS.red,
  high: COLORS.orange,
  medium: COLORS.yellow,
  low: COLORS.green,
  info: COLORS.muted
};

/**
 * Format duration in seconds to human readable string
 */
function fmtDuration(sec) {
  if (sec === null || sec === undefined || isNaN(sec)) return '-';
  sec = Math.round(Number(sec));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/**
 * Escape HTML special characters
 */
function esc(s) {
  return (s || '').toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Convert country code to flag emoji
 */
function countryCodeToFlag(code) {
  if (!code || code === 'PRIVATE' || code.length !== 2) return '';
  const offset = 127397;
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
}

/**
 * Get severity class for a command based on content
 */
function getSeverityForCommand(cmd) {
  const cmdLower = cmd.toLowerCase();
  if (cmdLower.includes('rm -rf') || cmdLower.includes('wget') || cmdLower.includes('curl') ||
      cmdLower.includes('chmod 777') || cmdLower.includes('/etc/passwd') || cmdLower.includes('nc -e')) {
    return 'critical';
  }
  if (cmdLower.includes('cat /etc') || cmdLower.includes('sudo') || cmdLower.includes('ssh') ||
      cmdLower.includes('scp') || cmdLower.includes('kill')) {
    return 'high';
  }
  if (cmdLower.includes('ps') || cmdLower.includes('netstat') || cmdLower.includes('ifconfig') ||
      cmdLower.includes('uname') || cmdLower.includes('whoami')) {
    return 'medium';
  }
  if (cmdLower.includes('ls') || cmdLower.includes('pwd') || cmdLower.includes('cd') ||
      cmdLower.includes('echo')) {
    return 'low';
  }
  return 'info';
}
