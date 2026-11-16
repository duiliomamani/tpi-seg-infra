<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>soporte. — Iniciar Sesión</title>
  <#if (properties.styles)?has_content>
    <#list properties.styles?split(' ') as style>
      <link rel="stylesheet" href="${url.resourcesPath}/${style}">
    </#list>
  <#else>
    <link rel="stylesheet" href="${url.resourcesPath}/css/login.css">
  </#if>
</head>
<body>
  <button type="button" class="theme-toggle" id="themeToggle" aria-label="Cambiar tema">🌙</button>

  <main class="login-screen">
    <section class="login-card">
      <div class="brand-lockup">
        <span class="brand-mark">S</span>
        <span>soporte<span class="brand-dot">.</span></span>
      </div>

      <div class="login-illustration" aria-hidden="true">
        <div class="orbit orbit-one"></div>
        <div class="orbit orbit-two"></div>
        <span class="headset">◖</span>
        <span class="spark spark-a">✦</span>
        <span class="spark spark-b">✳</span>
      </div>

      <p class="eyebrow">MESA DE AYUDA INTERNA</p>
      <h1>Iniciar Sesión</h1>
      <p class="login-copy">Ingresá con tus credenciales asignadas para acceder a la mesa de soporte seguro.</p>

      <#if message?has_content && ((message.type)!'') == 'error'>
        <div class="error-banner" role="alert">
          ${(message.summary!'Error al iniciar sesión')}
        </div>
      </#if>

      <form action="${url.loginAction}" method="post">
        <div class="field">
          <label for="username">Usuario o Correo</label>
          <input 
            id="username" 
            name="username" 
            type="text" 
            value="${(login.username!'')}" 
            required 
            autocomplete="username" 
            autofocus 
            placeholder="ej. alice o soporte"
          >
        </div>

        <div class="field">
          <label for="password">Contraseña</label>
          <input 
            id="password" 
            name="password" 
            type="password" 
            required 
            autocomplete="current-password" 
            placeholder="••••••••••••"
          >
        </div>

        <button type="submit" class="primary-button">
          Ingresar a Soporte <span aria-hidden="true">→</span>
        </button>
      </form>

      <div class="demo-accounts">
        <p class="demo-title">🔑 Credenciales de prueba disponibles:</p>
        <div class="demo-grid">
          <div><code>alice</code> / <code>alice-demo-pass</code> <small>(Colaboradora)</small></div>
          <div><code>soporte</code> / <code>soporte-demo-pass</code> <small>(Soporte L1)</small></div>
        </div>
      </div>

      <p class="privacy-note">
        <span class="lock-icon">⌑</span> Sesión protegida · acceso verificado por tu organización
      </p>
    </section>

    <footer class="login-footer">
      PoC local de soporte seguro <span>·</span> No uses credenciales reales
    </footer>
  </main>

  <script>
    (function() {
      const toggle = document.getElementById('themeToggle');
      const root = document.documentElement;
      const storageKey = 'soporte_keycloak_theme';
      
      function applyTheme(theme) {
        if (theme === 'dark') {
          root.setAttribute('data-theme', 'dark');
          toggle.textContent = '☀️';
          toggle.setAttribute('title', 'Cambiar a modo claro');
        } else if (theme === 'light') {
          root.setAttribute('data-theme', 'light');
          toggle.textContent = '🌙';
          toggle.setAttribute('title', 'Cambiar a modo oscuro');
        } else {
          root.removeAttribute('data-theme');
          const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          toggle.textContent = isDark ? '☀️' : '🌙';
          toggle.setAttribute('title', isDark ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro');
        }
      }

      const saved = localStorage.getItem(storageKey);
      if (saved) {
        applyTheme(saved);
      } else {
        applyTheme('system');
      }

      toggle.addEventListener('click', function() {
        const isDark = root.getAttribute('data-theme') === 'dark' || 
          (!root.hasAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
        const next = isDark ? 'light' : 'dark';
        localStorage.setItem(storageKey, next);
        applyTheme(next);
      });

      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() {
        if (!localStorage.getItem(storageKey)) {
          applyTheme('system');
        }
      });
    })();
  </script>
</body>
</html>
