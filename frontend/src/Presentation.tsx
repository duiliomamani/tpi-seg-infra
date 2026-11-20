import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, Bot, Cpu, Database, Key,
  ShieldCheck, ArrowRight, Server, Lock,
  AlertTriangle, UserX, ChevronLeft,
  ChevronRight, Fingerprint, FileCode2,
  Workflow, X, Maximize, Minimize
} from 'lucide-react';
import './presentation.css';

// Google Font injection for premium typography
const fontUrl = "https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap";

const Background = () => (
  <div className="fixed inset-0 overflow-hidden pointer-events-none z-0 bg-slate-950">
    {/* Deep Gradient Base */}
    <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-teal-950/40 to-blue-950/50"></div>

    {/* Glowing Orbs (Cyan & Orange) */}
    <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-cyan-500/20 rounded-full blur-[120px] mix-blend-screen"></div>
    <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-orange-500/10 rounded-full blur-[100px] mix-blend-screen"></div>

    {/* Tech Network SVG Pattern */}
    <div className="absolute inset-0 opacity-20">
      <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="network" x="0" y="0" width="100" height="100" patternUnits="userSpaceOnUse">
            <circle cx="50" cy="50" r="1" fill="#2dd4bf" />
            <circle cx="10" cy="10" r="1.5" fill="#38bdf8" />
            <path d="M50 50 L10 10 M50 50 L90 20 M50 50 L30 90 M10 10 L-10 40" stroke="rgba(255,255,255,0.05)" strokeWidth="1" fill="none" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#network)" />
      </svg>
    </div>
  </div>
);

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
}

const GlassCard = ({ children, className = "" }: GlassCardProps) => (
  <div className={`bg-slate-900/40 backdrop-blur-xl border border-white/10 shadow-[0_8px_32px_0_rgba(0,0,0,0.3)] rounded-3xl ${className}`}>
    {children}
  </div>
);

// --- SLIDES ---

const slides = [
  // SLIDE 1: Title
  {
    content: () => (
      <div className="flex flex-col items-center justify-center h-full text-center px-8 relative z-10 w-full max-w-5xl mx-auto">
        <div className="mb-8 inline-flex items-center gap-3 px-6 py-2 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 font-semibold tracking-widest text-sm uppercase">
          <ShieldAlert size={16} /> Unidad Nro. 6 · 2025
        </div>
        <h1 className="text-5xl md:text-7xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-cyan-100 to-teal-200 mb-6 leading-tight drop-shadow-lg">
          Seguridad en <br/> Inteligencia Artificial
        </h1>
        <p className="text-xl md:text-2xl text-slate-300 font-medium max-w-3xl mb-16">
          Vulnerabilidades OWASP y mecanismos de mitigación para asistentes y agentes autónomos.
        </p>

        <GlassCard className="px-8 py-6 flex items-center justify-between w-full max-w-3xl">
          <div className="text-left">
            <p className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">Integrantes</p>
            <p className="text-slate-200 font-medium">Duilio Mamani, Ebert Alemán, Braian Españon</p>
          </div>
          <div className="text-right">
            <p className="text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">Institución</p>
            <p className="text-slate-200 font-medium text-xl">UTN</p>
          </div>
        </GlassCard>
      </div>
    )
  },

  // SLIDE 2: El Problema
  {
    content: () => (
      <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-7xl mx-auto">
        <h2 className="text-4xl font-bold text-white mb-12 flex items-center gap-4">
          <span className="text-cyan-400">01.</span> Más allá del Chat
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
          <div>
            <p className="text-2xl text-slate-200 leading-relaxed font-light mb-8">
              Los LLMs ya no solo conversan. Ahora <strong className="text-cyan-300 font-semibold">analizan información, consultan sistemas privados y ejecutan acciones</strong> a través de herramientas.
            </p>
            <GlassCard className="p-6 border-l-4 border-l-orange-500">
              <h3 className="text-xl font-bold text-orange-400 mb-3 flex items-center gap-3">
                <AlertTriangle size={24} /> El Riesgo Principal
              </h3>
              <p className="text-slate-300 text-lg">
                La IA puede ser manipulada al procesar información de fuentes desconocidas o envenenadas (documentos, webs, bases de datos), interpretándolas como órdenes válidas.
              </p>
            </GlassCard>
          </div>

          <div className="relative flex justify-center items-center h-[400px]">
             {/* Abstract visual representation */}
             <div className="absolute w-64 h-64 bg-cyan-500/20 rounded-full blur-2xl animate-pulse"></div>
             <GlassCard className="w-80 h-80 flex flex-col items-center justify-center p-8 relative z-10 border-red-500/30 overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-b from-red-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <Bot size={80} className="text-cyan-300 mb-6" />
                <div className="h-px w-full bg-gradient-to-r from-transparent via-red-500/50 to-transparent my-4"></div>
                <ShieldAlert size={64} className="text-red-400" />
                <p className="mt-4 text-red-300 font-medium">Defensas Comprometidas</p>
             </GlassCard>
          </div>
        </div>
      </div>
    )
  },

  // SLIDE 3: La Amenaza - OWASP
  {
    content: () => (
      <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-7xl mx-auto">
        <h2 className="text-4xl font-bold text-white mb-10 flex items-center gap-4">
          <span className="text-orange-400">02.</span> Riesgos seleccionados · OWASP LLM Top 10 2025
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <GlassCard className="p-6 hover:-translate-y-2 transition-transform duration-300 border-t-4 border-t-red-500">
            <FileCode2 size={40} className="text-red-400 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">LLM01: Prompt Injection</h3>
            <p className="text-slate-300 text-sm">
              Instrucciones maliciosas ocultan comandos en prompts o documentos para desviar el comportamiento del agente.
            </p>
          </GlassCard>

          <GlassCard className="p-6 hover:-translate-y-2 transition-transform duration-300 border-t-4 border-t-yellow-500">
            <UserX size={40} className="text-yellow-400 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">LLM02: Sensitive Information Disclosure</h3>
            <p className="text-slate-300 text-sm">
              El modelo expone o divulga información sensible o confidencial a usuarios que no tienen los privilegios adecuados.
            </p>
          </GlassCard>

          <GlassCard className="p-6 hover:-translate-y-2 transition-transform duration-300 border-t-4 border-t-purple-500">
            <Database size={40} className="text-purple-400 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">LLM06: Excessive Agency</h3>
            <p className="text-slate-300 text-sm">
              El agente dispone de permisos o autonomía que pueden llevarlo a ejecutar acciones fuera del propósito autorizado.
            </p>
          </GlassCard>

          <GlassCard className="p-6 hover:-translate-y-2 transition-transform duration-300 border-t-4 border-t-cyan-500">
            <Workflow size={40} className="text-cyan-400 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">LLM04: Data and Model Poisoning</h3>
            <p className="text-slate-300 text-sm">
              Datos o modelos alterados pueden cambiar respuestas y decisiones del sistema.
            </p>
          </GlassCard>
        </div>
      </div>
    )
  },

  // SLIDE 4: La Solución
  {
    content: () => (
      <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-7xl mx-auto">
        <h2 className="text-4xl font-bold text-white mb-8 flex items-center gap-4">
          <span className="text-teal-400">03.</span> Defensa en Profundidad
        </h2>
        <p className="text-xl text-slate-300 mb-10 max-w-3xl">
          La seguridad debe abordarse mediante <strong className="text-white">controles externos</strong>, limitando la dependencia exclusiva de las restricciones del modelo.
        </p>

        <div className="grid grid-cols-2 gap-6 mb-10">
          <div className="flex gap-4 items-start">
            <div className="p-3 bg-teal-500/20 rounded-xl text-teal-400">
              <ShieldCheck size={32} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white mb-1">Guardrails y salida segura</h3>
              <p className="text-slate-400 text-sm">Valida esquemas, allowlists y límites; la UI representa la salida como texto, sin ejecutarla como HTML. No promete filtrar toda inyección semántica.</p>
            </div>
          </div>

          <div className="flex gap-4 items-start">
            <div className="p-3 bg-blue-500/20 rounded-xl text-blue-400">
              <Lock size={32} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white mb-1">Control de Acceso</h3>
              <p className="text-slate-400 text-sm">RBAC y ABAC verificados externamente (ej. OPA/Keycloak) antes de recuperar contexto o ejecutar herramientas.</p>
            </div>
          </div>

          <div className="flex gap-4 items-start">
            <div className="p-3 bg-indigo-500/20 rounded-xl text-indigo-400">
              <Database size={32} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white mb-1">Aprobación y cuarentena</h3>
              <p className="text-slate-400 text-sm">El estado de aprobación se comprueba antes del contexto. La PoC no valida firma/hash ni detecta semánticamente todas las instrucciones maliciosas.</p>
            </div>
          </div>

          <div className="flex gap-4 items-start">
            <div className="p-3 bg-emerald-500/20 rounded-xl text-emerald-400">
              <Key size={32} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white mb-1">Mínimo Privilegio</h3>
              <p className="text-slate-400 text-sm">El agente y el usuario solo deben contar con los permisos estrictamente necesarios.</p>
            </div>
          </div>
        </div>

        <GlassCard className="p-4 bg-white/5 grid gap-2 border-l-4 border-l-teal-500 text-sm text-slate-300">
          <p><strong className="text-cyan-300">Referencias:</strong> Google SAIF y Uber MCP Gateway. Son marcos externos, no componentes de esta PoC.</p>
          <p><strong className="text-cyan-300">Implementación de la PoC:</strong> Keycloak con OIDC Authorization Code + PKCE, OPA, servidor MCP y Qwen en Ollama.</p>
        </GlassCard>
      </div>
    )
  },

  // SLIDE 5: Flujo real de autorización
  {
    content: () => (
      <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-7xl mx-auto">
        <h2 className="text-4xl font-bold text-white mb-8 flex items-center gap-4">
          <span className="text-blue-400">04.</span> Flujo real de autorización
        </h2>

        <GlassCard className="p-8 w-full relative overflow-hidden">
          <div className="flex flex-col md:flex-row items-center justify-between gap-5 relative z-10">
            <div className="flex flex-col items-center gap-3 text-center">
              <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center border-2 border-slate-600">
                <Fingerprint size={36} className="text-slate-300" />
              </div>
              <span className="text-slate-300 font-medium">Usuario<br />Chat + BFF</span>
            </div>

            <ArrowRight size={28} className="text-slate-600 hidden md:block" />

            <div className="flex flex-col items-center gap-3 text-center">
              <div className="w-20 h-20 bg-cyan-900/50 rounded-2xl flex items-center justify-center border border-cyan-500/50">
                <Bot size={42} className="text-cyan-400" />
              </div>
              <span className="text-cyan-300 font-medium">Qwen<br />Ollama local</span>
            </div>

            <ArrowRight size={28} className="text-slate-600 hidden md:block" />

            <div className="flex flex-col items-center gap-3 text-center">
              <div className="w-20 h-20 bg-indigo-900/50 rounded-xl flex items-center justify-center border border-indigo-500/50">
                <Server size={42} className="text-indigo-400" />
              </div>
              <span className="text-indigo-300 font-medium">Servidor MCP<br />valida JWT</span>
            </div>

            <ArrowRight size={28} className="text-slate-600 hidden md:block" />

            <div className="flex flex-col items-center gap-3 text-center">
              <div className="w-20 h-20 bg-emerald-900/40 rounded-xl flex items-center justify-center border border-emerald-500/40">
                <ShieldCheck size={42} className="text-emerald-400" />
              </div>
              <span className="text-emerald-300 font-medium">OPA<br />decide por recurso</span>
            </div>

            <ArrowRight size={28} className="text-slate-600 hidden md:block" />

            <div className="flex flex-col items-center gap-3 text-center">
              <div className="w-20 h-20 bg-slate-800 rounded-xl flex items-center justify-center border border-slate-600">
                <Database size={42} className="text-slate-300" />
              </div>
              <span className="text-slate-300 font-medium">SQLite sintética<br />Keycloak local</span>
            </div>
          </div>

          <p className="mt-8 text-center text-slate-300 text-sm bg-slate-950/50 p-4 rounded-xl">
            El modelo propone la herramienta; el BFF valida nombre y argumentos. MCP verifica el token y consulta OPA. Los efectos quedan limitados a datos sintéticos y al realm local <code>support-poc</code>.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
            <div className="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-xl">
              <h3 className="text-emerald-300 font-bold mb-2">Modo Seguro</h3>
              <p className="text-slate-300 text-sm">Las lecturas se autorizan por usuario y recurso. Las acciones sensibles requieren el rol <code>support_admin</code>, confirmación autenticada y aprobación de OPA; las solicitudes no autorizadas se deniegan.</p>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl">
              <h3 className="text-red-300 font-bold mb-2">Modo Vulnerable</h3>
              <p className="text-slate-300 text-sm">La demo omite controles seleccionados para mostrar el impacto en tickets y grupos sintéticos, precios ficticios o el MFA de una cuenta local.</p>
            </div>
          </div>
        </GlassCard>
      </div>
    )
  },

  // SLIDE 6: Escenarios de Soporte Empresarial
  {
    content: () => {
      return (
        <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-7xl mx-auto">
          <h2 className="text-4xl font-bold text-white mb-8 flex items-center gap-4">
            <span className="text-cyan-400">05.</span> Escenarios de Soporte Empresarial
          </h2>
          <GlassCard className="mx-auto flex max-w-4xl items-center gap-8 p-10 md:p-14">
            <Workflow size={48} className="shrink-0 text-cyan-300" />
            <p className="text-xl leading-relaxed text-slate-200">
              La demo presenta un asistente de IA para soporte empresarial: responde consultas, ayuda a gestionar solicitudes y aplica controles de seguridad antes de acceder a información o ejecutar acciones.
            </p>
          </GlassCard>
        </div>
      );
    }
  },

  // SLIDE 7: Conclusión
  {
    content: (onExit?: () => void) => (
      <div className="flex flex-col items-center justify-center h-full text-center px-8 relative z-10 w-full max-w-4xl mx-auto">

        <div className="mb-6 p-5 bg-cyan-500/10 rounded-full">
          <Cpu size={56} className="text-cyan-400" />
        </div>

        <h2 className="text-4xl md:text-5xl font-extrabold text-white mb-6 leading-tight">
          La IA no es el <br/>
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">último filtro de seguridad.</span>
        </h2>

        <GlassCard className="p-8 w-full mb-8">
          <p className="text-xl md:text-2xl text-slate-300 font-light leading-relaxed">
            Las decisiones críticas de acceso y las operaciones sensibles requieren verificaciones
            <strong className="text-white font-semibold"> independientes</strong>, arquitecturas seguras y barreras de control
            sobre los datos de entrada y salida.
          </p>
        </GlassCard>

        {onExit && (
          <button
            onClick={onExit}
            className="inline-flex items-center gap-3 px-8 py-3.5 rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 hover:brightness-110 text-slate-950 font-bold text-base shadow-[0_0_25px_rgba(45,212,191,0.45)] transition-all transform hover:scale-105 active:scale-95 cursor-pointer pointer-events-auto"
          >
            <span>Ir a la demo</span>
            <ArrowRight size={20} />
          </button>
        )}

      </div>
    )
  },

  // SLIDE 8: Fuentes
  {
    content: () => (
      <div className="flex flex-col h-full justify-center px-12 relative z-10 max-w-6xl mx-auto">
        <h2 className="text-4xl font-bold text-white mb-10">Fuentes principales</h2>
        <GlassCard className="p-10 grid gap-6 text-lg">
          <a className="text-cyan-300 hover:text-cyan-100 underline" href="https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/" target="_blank" rel="noreferrer">OWASP Top 10 for LLM Applications 2025</a>
          <a className="text-cyan-300 hover:text-cyan-100 underline" href="https://owasp.org/projects/mcp-top-10?tab=top10" target="_blank" rel="noreferrer">OWASP MCP Top 10 2025</a>
          <a className="text-cyan-300 hover:text-cyan-100 underline" href="https://safety.google/safety/saif/" target="_blank" rel="noreferrer">Google Secure AI Framework (SAIF)</a>
          <a className="text-cyan-300 hover:text-cyan-100 underline" href="https://www.uber.com/us/en/blog/designing-mcp-gateway/" target="_blank" rel="noreferrer">Uber, Designing MCP Gateway</a>
          <p className="text-slate-400 text-sm">SAIF y Uber MCP Gateway son referencias externas. La PoC implementa Keycloak, OPA, MCP y Qwen/Ollama.</p>
        </GlassCard>
      </div>
    )
  }
];

export interface PresentationProps {
  onExit?: () => void;
}

export default function Presentation({ onExit }: PresentationProps) {
  const [currentSlide, setCurrentSlide] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const nextSlide = () => setCurrentSlide((prev) => Math.min(prev + 1, slides.length - 1));
  const prevSlide = () => setCurrentSlide((prev) => Math.max(prev - 1, 0));

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
      setIsFullscreen(true);
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
      }
      setIsFullscreen(false);
    }
  };

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === ' ') {
        e.preventDefault();
        nextSlide();
      }
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        prevSlide();
      }
      if (e.key === 'Escape' && onExit && !document.fullscreenElement) {
        onExit();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onExit]);

  return (
    <>
      <style dangerouslySetInnerHTML={{__html: `@import url('${fontUrl}'); .presentation-wrapper { font-family: 'Plus Jakarta Sans', sans-serif; }`}} />

      <div className="presentation-wrapper fixed inset-0 z-50 w-full h-screen overflow-hidden text-slate-100 select-none bg-slate-950">
        <Background />

        {/* Floating Top Controls */}
        <div className="absolute top-6 right-6 z-40 flex items-center gap-3">
          <button
            onClick={toggleFullscreen}
            className="p-2.5 rounded-full bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700 backdrop-blur-md transition-all shadow-lg"
            title={isFullscreen ? "Salir de pantalla completa" : "Pantalla completa"}
            aria-label="Pantalla completa"
          >
            {isFullscreen ? <Minimize size={18} /> : <Maximize size={18} />}
          </button>
          {onExit && (
            <button
              onClick={onExit}
              className="flex items-center gap-2 px-4 py-2 rounded-full bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700 backdrop-blur-md transition-all shadow-lg text-sm font-medium"
              title="Volver a la aplicación"
            >
              <X size={18} />
              <span>Volver a la App</span>
            </button>
          )}
        </div>

        {/* Clickable side navigation zones */}
        <div className="absolute top-0 left-0 w-[15%] h-full z-20 cursor-pointer opacity-0 hover:opacity-100 flex items-center justify-start pl-4 transition-opacity" onClick={prevSlide}>
          <div className="bg-white/10 p-4 rounded-full backdrop-blur-md text-white">
             <ChevronLeft size={32} />
          </div>
        </div>
        <div className="absolute top-0 right-0 w-[15%] h-full z-20 cursor-pointer opacity-0 hover:opacity-100 flex items-center justify-end pr-4 transition-opacity" onClick={nextSlide}>
          <div className="bg-white/10 p-4 rounded-full backdrop-blur-md text-white">
             <ChevronRight size={32} />
          </div>
        </div>

        {/* Slide Content */}
        <div className="relative w-full h-full z-10 transition-opacity duration-500 flex items-center justify-center">
          {slides[currentSlide].content(onExit)}
        </div>

        {/* Progress Bar & Indicators */}
        <div className="absolute bottom-8 left-0 right-0 flex flex-col items-center justify-center z-30 gap-4 pointer-events-none">
          <div className="flex gap-2 pointer-events-auto">
            {slides.map((_, idx) => (
              <button
                key={idx}
                onClick={() => setCurrentSlide(idx)}
                className={`h-2 rounded-full transition-all duration-300 ${
                  currentSlide === idx ? 'w-8 bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.5)]' : 'w-2 bg-slate-600 hover:bg-slate-400'
                }`}
                aria-label={`Ir a diapositiva ${idx + 1}`}
              />
            ))}
          </div>
          <span className="text-slate-500 text-xs font-semibold uppercase tracking-widest font-mono">
            {currentSlide + 1} / {slides.length}
          </span>
        </div>
      </div>
    </>
  );
}
