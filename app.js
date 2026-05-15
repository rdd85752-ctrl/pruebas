/* ═══════════════════════════════════════════════════════════════
   TODO APP — app.js
   - Supabase SDK v2 (protección SQL injection por parámetros)
   - Auth con correo/contraseña
   - CRUD completo de tareas
   - RLS: cada usuario solo ve/modifica sus propias tareas
═══════════════════════════════════════════════════════════════ */

// ── Configuración Supabase ─────────────────────────────────────
// En producción, estas variables vendrían de un archivo .env
// procesado por un bundler (Vite, Webpack) o un servidor backend.
// Para uso directo en HTML se exponen aquí (el anon key es público
// por diseño en Supabase; la seguridad real la aplica el RLS).

const SUPABASE_URL      = 'https://mhkkmtksrdjirsioljyd.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1oa2ttdGtzcmRqaXJzaW9sanlkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg4MDY5MDYsImV4cCI6MjA5NDM4MjkwNn0.SjPGej7oodOcHkDD2Zy08xH031rYx0Gil1WVSw4YdPk';

// Inicializar cliente de Supabase (el SDK usa consultas parametrizadas
// internamente, eliminando el riesgo de inyección SQL).
const { createClient } = supabase;
const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ── Estado de la app ──────────────────────────────────────────
let currentUser  = null;
let allTasks     = [];
let activeFilter = 'todas';

// ── Utilidades DOM ────────────────────────────────────────────
const $  = (id)  => document.getElementById(id);
const qs = (sel) => document.querySelector(sel);

function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  $(`${name}-screen`).classList.add('active');
}

function showMsg(elId, text, type = 'error') {
  const el = $(elId);
  el.textContent  = text;
  el.className    = `msg ${type}`;
}

function hideMsg(elId) {
  const el = $(elId);
  el.className = 'msg hidden';
  el.textContent = '';
}

let toastTimer;
function showToast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  requestAnimationFrame(() => t.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => t.classList.add('hidden'), 220);
  }, 2600);
}

// ── Validaciones del lado cliente ─────────────────────────────
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

function validateEmail(email) {
  if (!email || email.trim().length === 0) return 'Ingresa tu correo.';
  if (email.length > 254)                  return 'El correo es demasiado largo.';
  if (!EMAIL_REGEX.test(email.trim()))     return 'El formato del correo no es válido.';
  return null;
}

function validatePassword(pw, minLen = 6) {
  if (!pw || pw.length < minLen) return `La contraseña debe tener al menos ${minLen} caracteres.`;
  if (pw.length > 128)           return 'La contraseña es demasiado larga.';
  return null;
}

function validateDescription(desc) {
  const d = (desc || '').trim();
  if (d.length === 0)   return 'La descripción no puede estar vacía.';
  if (d.length > 500)   return 'La descripción no puede superar 500 caracteres.';
  return null;
}

// ── Auth: Tabs ─────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.form-section').forEach(s => s.classList.remove('active'));
    tab.classList.add('active');
    $(`form-${tab.dataset.tab}`).classList.add('active');
    hideMsg('auth-msg');
  });
});

// ── Auth: Login ────────────────────────────────────────────────
$('btn-login').addEventListener('click', async () => {
  hideMsg('auth-msg');
  const email = $('login-email').value.trim().toLowerCase();
  const pass  = $('login-password').value;

  const emailErr = validateEmail(email);
  if (emailErr) { showMsg('auth-msg', emailErr); return; }
  const passErr = validatePassword(pass);
  if (passErr)  { showMsg('auth-msg', passErr); return; }

  $('btn-login').disabled = true;
  $('btn-login').textContent = 'Ingresando…';

  try {
    const { data, error } = await sb.auth.signInWithPassword({ email, password: pass });
    if (error) throw error;
    currentUser = data.user;
    await initApp();
  } catch (err) {
    showMsg('auth-msg', traducirError(err.message));
  } finally {
    $('btn-login').disabled = false;
    $('btn-login').textContent = 'Ingresar';
  }
});

// ── Auth: Register ─────────────────────────────────────────────
$('btn-register').addEventListener('click', async () => {
  hideMsg('auth-msg');
  const name  = $('reg-name').value.trim();
  const email = $('reg-email').value.trim().toLowerCase();
  const pass  = $('reg-password').value;

  if (name.length > 100) { showMsg('auth-msg', 'El nombre no puede superar 100 caracteres.'); return; }
  const emailErr = validateEmail(email);
  if (emailErr) { showMsg('auth-msg', emailErr); return; }
  const passErr = validatePassword(pass, 8);
  if (passErr)  { showMsg('auth-msg', passErr); return; }

  $('btn-register').disabled = true;
  $('btn-register').textContent = 'Creando cuenta…';

  try {
    // 1. Crear usuario en Supabase Auth
    const { data, error } = await sb.auth.signUp({
      email,
      password: pass,
      options: { data: { nombre: name || email.split('@')[0] } }
    });
    if (error) throw error;

    // 2. Insertar perfil en la tabla usuarios (RLS protege el resto)
    if (data.user) {
      await sb.from('usuarios').upsert({
        id:     data.user.id,
        correo: email,
        nombre: name || email.split('@')[0],
        // contrasena_hash no se inserta aquí; Supabase Auth lo gestiona
      }, { onConflict: 'id' });

      currentUser = data.user;
      await initApp();
    } else {
      showMsg('auth-msg', 'Revisa tu correo para confirmar tu cuenta.', 'success');
    }
  } catch (err) {
    showMsg('auth-msg', traducirError(err.message));
  } finally {
    $('btn-register').disabled = false;
    $('btn-register').textContent = 'Crear cuenta';
  }
});

// ── Auth: Logout ───────────────────────────────────────────────
$('btn-logout').addEventListener('click', async () => {
  await sb.auth.signOut();
  currentUser = null;
  allTasks    = [];
  showScreen('auth');
  $('login-email').value    = '';
  $('login-password').value = '';
});

// ── Inicializar sesión existente ───────────────────────────────
(async () => {
  const { data: { session } } = await sb.auth.getSession();
  if (session?.user) {
    currentUser = session.user;
    await initApp();
  } else {
    showScreen('auth');
  }
})();

// Escuchar cambios de sesión
sb.auth.onAuthStateChange(async (_event, session) => {
  if (!session) {
    currentUser = null;
    showScreen('auth');
  }
});

// ── Inicializar App ────────────────────────────────────────────
async function initApp() {
  const name = currentUser.user_metadata?.nombre
    || currentUser.email.split('@')[0];
  $('user-name').textContent = name;
  showScreen('app');
  await loadTasks();
}

// ── Cargar Tareas ──────────────────────────────────────────────
// El SDK envía el JWT del usuario en Authorization; el RLS de Supabase
// filtra automáticamente: solo devuelve tareas donde usuario_id = auth.uid()
async function loadTasks() {
  try {
    const { data, error } = await sb
      .from('tareas')
      .select('*')
      .order('creado_en', { ascending: false });

    if (error) throw error;
    allTasks = data || [];
    renderTasks();
    updateStats();
  } catch (err) {
    showToast('Error al cargar tareas: ' + traducirError(err.message));
  }
}

// ── Renderizar Tareas ──────────────────────────────────────────
function renderTasks() {
  const list    = $('task-list');
  const empty   = $('empty-state');
  const filtered = activeFilter === 'todas'
    ? allTasks
    : allTasks.filter(t => t.estado === activeFilter);

  list.innerHTML = '';

  if (filtered.length === 0) {
    list.appendChild(empty);
    empty.style.display = 'flex';
    return;
  }

  empty.style.display = 'none';
  filtered.forEach(task => list.appendChild(buildTaskCard(task)));
}

function buildTaskCard(task) {
  const card = document.createElement('div');
  card.className = `task-card ${task.estado === 'completada' ? 'completed' : ''}`;
  card.dataset.id = task.id;

  const isOver = task.fecha_limite
    && task.estado !== 'completada'
    && new Date(task.fecha_limite) < new Date();

  card.innerHTML = `
    <div class="task-check ${task.estado === 'completada' ? 'checked' : ''}"
         title="${task.estado === 'completada' ? 'Marcar pendiente' : 'Marcar completada'}">
    </div>
    <div class="task-body">
      <p class="task-desc ${task.estado === 'completada' ? 'done-text' : ''}">
        ${escapeHtml(task.descripcion)}
      </p>
      <div class="task-meta">
        <span class="task-num">#${task.numero_tarea ?? '–'}</span>
        <span class="priority-badge ${task.prioridad}">${labelPrioridad(task.prioridad)}</span>
        ${task.fecha_limite
          ? `<span class="task-date ${isOver ? 'overdue' : ''}">
               ${isOver ? '⚠ ' : ''}${formatDate(task.fecha_limite)}
             </span>`
          : ''}
      </div>
    </div>
    <div class="task-actions">
      <button class="btn-icon edit-btn" title="Editar">
        <svg width="15" height="15" viewBox="0 0 15 15" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M10.5 1.5l3 3-9 9H1.5v-3l9-9z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
        </svg>
      </button>
      <button class="btn-icon danger delete-btn" title="Eliminar">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M2 3.5h10M5.5 3.5V2.5h3v1M3.5 3.5l.5 8h6l.5-8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    </div>`;

  // Checkbox toggle
  card.querySelector('.task-check').addEventListener('click', () => toggleTask(task));

  // Edit
  card.querySelector('.edit-btn').addEventListener('click', () => openEditModal(task));

  // Delete
  card.querySelector('.delete-btn').addEventListener('click', () => deleteTask(task.id));

  return card;
}

// ── Contador de caracteres ─────────────────────────────────────
$('new-task-desc').addEventListener('input', function () {
  $('char-count').textContent = `${this.value.length} / 500`;
});

$('edit-desc').addEventListener('input', function () {
  $('edit-char-count').textContent = `${this.value.length} / 500`;
});

// ── Agregar Tarea ──────────────────────────────────────────────
$('btn-add-task').addEventListener('click', async () => {
  hideMsg('task-msg');
  const desc     = $('new-task-desc').value;
  const priority = $('new-task-priority').value;
  const date     = $('new-task-date').value || null;

  const err = validateDescription(desc);
  if (err) { showMsg('task-msg', err); return; }

  $('btn-add-task').disabled = true;
  $('btn-add-task').textContent = 'Agregando…';

  try {
    // El SDK envía los datos como JSON parametrizado → sin SQL injection
    const { data, error } = await sb.from('tareas').insert({
      usuario_id:   currentUser.id,
      descripcion:  desc.trim(),
      prioridad:    priority,
      fecha_limite: date,
      estado:       'pendiente',
    }).select().single();

    if (error) throw error;

    allTasks.unshift(data);
    renderTasks();
    updateStats();

    $('new-task-desc').value  = '';
    $('new-task-date').value  = '';
    $('char-count').textContent = '0 / 500';
    showToast('Tarea agregada ✓');
  } catch (err) {
    showMsg('task-msg', traducirError(err.message));
  } finally {
    $('btn-add-task').disabled = false;
    $('btn-add-task').textContent = 'Agregar';
  }
});

// Enter en el campo de texto también agrega tarea
$('new-task-desc').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    $('btn-add-task').click();
  }
});

// ── Completar / Reactivar Tarea ────────────────────────────────
async function toggleTask(task) {
  const nuevoEstado = task.estado === 'completada' ? 'pendiente' : 'completada';

  // Optimistic UI
  task.estado = nuevoEstado;
  renderTasks();
  updateStats();

  try {
    const { error } = await sb
      .from('tareas')
      .update({ estado: nuevoEstado })
      .eq('id', task.id);

    if (error) {
      // Revertir en caso de error
      task.estado = nuevoEstado === 'completada' ? 'pendiente' : 'completada';
      renderTasks();
      updateStats();
      throw error;
    }

    showToast(nuevoEstado === 'completada' ? '¡Tarea completada! ✓' : 'Tarea reactivada');
  } catch (err) {
    showToast('Error: ' + traducirError(err.message));
  }
}

// ── Editar Tarea ───────────────────────────────────────────────
function openEditModal(task) {
  $('edit-task-id').value  = task.id;
  $('edit-desc').value     = task.descripcion;
  $('edit-priority').value = task.prioridad;
  $('edit-date').value     = task.fecha_limite ? task.fecha_limite.substring(0, 10) : '';
  $('edit-char-count').textContent = `${task.descripcion.length} / 500`;
  hideMsg('edit-msg');
  $('edit-modal').classList.remove('hidden');
}

$('btn-cancel-edit').addEventListener('click', () => {
  $('edit-modal').classList.add('hidden');
});

$('edit-modal').addEventListener('click', (e) => {
  if (e.target === $('edit-modal')) $('edit-modal').classList.add('hidden');
});

$('btn-save-edit').addEventListener('click', async () => {
  hideMsg('edit-msg');
  const id       = $('edit-task-id').value;
  const desc     = $('edit-desc').value;
  const priority = $('edit-priority').value;
  const date     = $('edit-date').value || null;

  const err = validateDescription(desc);
  if (err) { showMsg('edit-msg', err); return; }

  $('btn-save-edit').disabled = true;
  $('btn-save-edit').textContent = 'Guardando…';

  try {
    const { data, error } = await sb
      .from('tareas')
      .update({
        descripcion:  desc.trim(),
        prioridad:    priority,
        fecha_limite: date,
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    // Actualizar estado local
    const idx = allTasks.findIndex(t => t.id === id);
    if (idx !== -1) allTasks[idx] = data;
    renderTasks();

    $('edit-modal').classList.add('hidden');
    showToast('Tarea actualizada ✓');
  } catch (err) {
    showMsg('edit-msg', traducirError(err.message));
  } finally {
    $('btn-save-edit').disabled = false;
    $('btn-save-edit').textContent = 'Guardar';
  }
});

// ── Eliminar Tarea ─────────────────────────────────────────────
async function deleteTask(id) {
  if (!confirm('¿Eliminar esta tarea?')) return;

  try {
    const { error } = await sb.from('tareas').delete().eq('id', id);
    if (error) throw error;

    allTasks = allTasks.filter(t => t.id !== id);
    renderTasks();
    updateStats();
    showToast('Tarea eliminada');
  } catch (err) {
    showToast('Error al eliminar: ' + traducirError(err.message));
  }
}

// ── Filtros ────────────────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderTasks();
  });
});

// ── Estadísticas ───────────────────────────────────────────────
function updateStats() {
  const total     = allTasks.length;
  const completed = allTasks.filter(t => t.estado === 'completada').length;
  const pending   = total - completed;

  $('stat-total').textContent   = total;
  $('stat-pending').textContent = pending;
  $('stat-done').textContent    = completed;
}

// ── Helpers ────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  return d.toLocaleDateString('es-MX', { day: '2-digit', month: 'short', year: 'numeric' });
}

function labelPrioridad(p) {
  return { baja: '🟢 Baja', media: '🟡 Media', alta: '🔴 Alta' }[p] || p;
}

function traducirError(msg = '') {
  if (msg.includes('Invalid login credentials')) return 'Correo o contraseña incorrectos.';
  if (msg.includes('Email not confirmed'))        return 'Confirma tu correo antes de ingresar.';
  if (msg.includes('already registered'))         return 'Este correo ya está registrado.';
  if (msg.includes('Password should be'))         return 'La contraseña debe tener al menos 6 caracteres.';
  if (msg.includes('network'))                    return 'Error de conexión. Revisa tu internet.';
  return msg || 'Ocurrió un error inesperado.';
}
