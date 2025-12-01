import React, { useState, useEffect } from 'react';
import { shells, generatePayload } from './data/shells';
import { Copy, Terminal, Shield, Wifi, Server, Check, Lock, Filter, Zap, Code } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

function App() {
  const [ip, setIp] = useState('10.10.10.10');
  const [port, setPort] = useState('4444');
  const [selectedOs, setSelectedOs] = useState('linux');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedId, setCopiedId] = useState(null);
  const [obfuscation, setObfuscation] = useState('none');
  const [selectedTag, setSelectedTag] = useState('all');
  const [selectedLanguage, setSelectedLanguage] = useState('all');

  // Extract unique tags and languages
  const allTags = ['all', ...new Set(shells.flatMap(s => s.tags || []))].sort();
  const allLanguages = ['all', ...new Set(shells.map(s => s.language))].sort();

  const filteredShells = shells.filter(shell =>
    shell.os === selectedOs &&
    (selectedTag === 'all' || (shell.tags && shell.tags.includes(selectedTag))) &&
    (selectedLanguage === 'all' || shell.language === selectedLanguage) &&
    (shell.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      shell.language.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="min-h-screen bg-background text-text selection:bg-primary selection:text-background font-mono overflow-hidden relative">
      {/* Background Matrix Effect (Simplified) */}
      <div className="absolute inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(0,255,65,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.05)_1px,transparent_1px)] bg-[size:20px_20px]"></div>

      <div className="container mx-auto p-6 relative z-10 max-w-7xl">
        <header className="mb-8 flex items-center justify-between border-b border-border pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-surface border border-primary rounded shadow-[0_0_10px_rgba(0,255,65,0.3)]">
              <Shield className="w-8 h-8 text-primary animate-pulse-slow" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tighter text-white">
                SAFESPACE <span className="text-primary">SHELL_GEN</span>
              </h1>
              <p className="text-xs text-muted uppercase tracking-widest flex items-center gap-2">
                <Zap className="w-3 h-3 text-accent" /> Testphase Edition
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-sm text-muted">
            <div className="flex items-center gap-2">
              <Wifi className="w-4 h-4 text-primary" />
              <span>CONNECTED</span>
            </div>
            <div className="h-4 w-[1px] bg-border"></div>
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4" />
              <span>v3.0.0 (MASSIVE)</span>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Configuration Panel */}
          <div className="lg:col-span-4 space-y-6">
            <div className="bg-surface border border-border p-6 rounded-lg shadow-lg backdrop-blur-sm">
              <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-accent" />
                CONFIGURATION
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs uppercase tracking-wider text-muted mb-1">LHOST (IP Address)</label>
                  <input
                    type="text"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    className="w-full bg-background border border-border rounded p-2 text-primary focus:border-primary focus:outline-none focus:shadow-[0_0_5px_rgba(0,255,65,0.5)] transition-all"
                  />
                </div>

                <div>
                  <label className="block text-xs uppercase tracking-wider text-muted mb-1">LPORT (Port)</label>
                  <input
                    type="text"
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    className="w-full bg-background border border-border rounded p-2 text-accent focus:border-accent focus:outline-none focus:shadow-[0_0_5px_rgba(255,0,60,0.5)] transition-all"
                  />
                </div>

                <div>
                  <label className="block text-xs uppercase tracking-wider text-muted mb-1">Target OS</label>
                  <div className="flex gap-2">
                    {['linux', 'windows', 'mac'].map(os => (
                      <button
                        key={os}
                        onClick={() => setSelectedOs(os)}
                        className={`flex-1 py-2 px-4 rounded border capitalize transition-all ${selectedOs === os
                            ? 'bg-primary/10 border-primary text-primary shadow-[0_0_10px_rgba(0,255,65,0.2)]'
                            : 'bg-background border-border text-muted hover:border-muted'
                          }`}
                      >
                        {os}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="pt-4 border-t border-border">
                  <label className="block text-xs uppercase tracking-wider text-muted mb-2 flex items-center gap-2">
                    <Lock className="w-3 h-3" /> Obfuscation
                  </label>
                  <select
                    value={obfuscation}
                    onChange={(e) => setObfuscation(e.target.value)}
                    className="w-full bg-background border border-border rounded p-2 text-sm focus:border-primary focus:outline-none"
                  >
                    <option value="none">None (Raw)</option>
                    <option value="base64">Base64 Encoded</option>
                    <option value="url">URL Encoded</option>
                    <option value="hex">Hex Encoded</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Listener Command Preview */}
            <div className="bg-surface border border-border p-6 rounded-lg shadow-lg">
              <h2 className="text-sm font-bold text-white mb-3 uppercase tracking-wider">Listener Command</h2>
              <div className="relative group">
                <div className="bg-background p-3 rounded border border-border font-mono text-sm text-muted break-all">
                  nc -lvnp {port}
                </div>
                <button
                  onClick={() => handleCopy(`nc -lvnp ${port}`, 'listener')}
                  className="absolute top-2 right-2 p-1.5 bg-surface border border-border rounded hover:border-primary hover:text-primary transition-colors"
                >
                  {copiedId === 'listener' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          {/* Shells List */}
          <div className="lg:col-span-8">
            <div className="mb-4 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  AVAILABLE PAYLOADS
                  <span className="text-xs font-normal text-muted bg-surface px-2 py-1 rounded border border-border">
                    {filteredShells.length}
                  </span>
                </h2>

                <div className="flex items-center gap-2">
                  {/* Language Filter */}
                  <div className="flex items-center gap-2">
                    <Code className="w-4 h-4 text-muted" />
                    <select
                      value={selectedLanguage}
                      onChange={(e) => setSelectedLanguage(e.target.value)}
                      className="bg-surface border border-border rounded px-3 py-1 text-sm focus:border-primary focus:outline-none max-w-[120px]"
                    >
                      {allLanguages.map(lang => (
                        <option key={lang} value={lang}>{lang === 'all' ? 'ALL LANGS' : lang.toUpperCase()}</option>
                      ))}
                    </select>
                  </div>

                  {/* Tag Filter */}
                  <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-muted" />
                    <select
                      value={selectedTag}
                      onChange={(e) => setSelectedTag(e.target.value)}
                      className="bg-surface border border-border rounded px-3 py-1 text-sm focus:border-primary focus:outline-none max-w-[120px]"
                    >
                      {allTags.map(tag => (
                        <option key={tag} value={tag}>{tag === 'all' ? 'ALL TAGS' : tag.toUpperCase()}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <input
                type="text"
                placeholder="Search payloads..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-surface border border-border rounded px-4 py-2 text-sm focus:border-primary focus:outline-none"
              />
            </div>

            <div className="space-y-4 h-[calc(100vh-300px)] overflow-y-auto pr-2 custom-scrollbar">
              <AnimatePresence>
                {filteredShells.map((shell, index) => {
                  const payload = generatePayload(shell.id, ip, port, obfuscation);
                  return (
                    <motion.div
                      key={shell.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      transition={{ delay: Math.min(index * 0.05, 0.5) }} // Cap delay for large lists
                      className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-primary font-bold">{shell.name}</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-background border border-border text-muted uppercase">{shell.language}</span>
                          {shell.tags && shell.tags.map(tag => (
                            <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 border border-accent/20 text-accent uppercase tracking-wider">
                              {tag}
                            </span>
                          ))}
                        </div>
                        <button
                          onClick={() => handleCopy(payload, shell.id)}
                          className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium transition-all ${copiedId === shell.id
                              ? 'bg-primary text-background'
                              : 'bg-background border border-border hover:border-primary hover:text-primary'
                            }`}
                        >
                          {copiedId === shell.id ? (
                            <>
                              <Check className="w-4 h-4" />
                              <span>COPIED</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-4 h-4" />
                              <span>COPY</span>
                            </>
                          )}
                        </button>
                      </div>

                      <div className="bg-background p-3 rounded border border-border font-mono text-sm text-muted break-all relative overflow-hidden">
                        {payload}
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/5 to-transparent -translate-x-full group-hover:animate-[shimmer_2s_infinite]"></div>
                      </div>
                      <p className="text-xs text-muted mt-2">{shell.description}</p>
                    </motion.div>
                  );
                })}
              </AnimatePresence>

              {filteredShells.length === 0 && (
                <div className="text-center py-12 text-muted">
                  <Terminal className="w-12 h-12 mx-auto mb-4 opacity-20" />
                  <p>No payloads found matching your criteria.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
