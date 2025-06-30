<?php
// Configuración de CORS para permitir solicitudes desde tu frontend Vue.js
// En producción, CAMBIA '*' por el dominio exacto de tu frontend.
// Ejemplo: header("Access-Control-Allow-Origin: https://3dlirantes.com.ar");
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, DELETE, PUT, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// Si es una solicitud OPTIONS (pre-flight de CORS), responder con éxito y salir.
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); // No Content
    exit;
}

// Incluir el autoloader de Composer.
// Asume que la carpeta 'vendor' está un nivel arriba de 'api'.
require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use Psr\SimpleCache\CacheInterface; // Interfaz para la caché

// --- CONFIGURACIÓN DE LA API Y FIREBASE ---

// Directorio base donde se subirán las imágenes.
// __DIR__ es la carpeta actual (api/). '/../' sube un nivel (a la raíz del proyecto).
// Luego, '/public/uploads/products/' es la ruta relativa desde la raíz del proyecto.
$upload_dir_base = __DIR__ . '/../uploads/products/';

// URL base pública para acceder a las imágenes desde el navegador.
// AJUSTA ESTO a tu dominio real.
$base_url = 'https://3dlirantes.com.ar/uploads/products/';

// Si estás en un entorno de desarrollo local (ej. XAMPP/WAMP), ajusta la URL base.
// Asegúrate de que 'tu_proyecto' sea el nombre de la carpeta raíz de tu proyecto en localhost.
if ($_SERVER['HTTP_HOST'] === 'localhost' || $_SERVER['HTTP_HOST'] === '127.0.0.1') {
    $base_url = 'http://localhost/tu_proyecto/uploads/products/'; // <--- CAMBIA 'tu_proyecto'
}

// Tu Project ID de Firebase. Lo encuentras en la configuración de tu proyecto en la consola de Firebase.
const FIREBASE_PROJECT_ID = 'dlirantes';

// URL para obtener las claves públicas de Google. No cambiar.
const GOOGLE_PUBLIC_KEYS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

// Tiempo de vida de la caché para las claves públicas (en segundos). Recomendado 1 hora.
const PUBLIC_KEYS_CACHE_TTL = 3600; // 1 hora

// --- CLASE DE CACHÉ SIMPLE PARA CLAVES PÚBLICAS (EN MEMORIA) ---
// NOTA: Esta caché es muy básica y solo funciona por solicitud.
// Para producción, se recomienda una librería de caché persistente (ej. basada en archivos, APCu, Redis).
class SimpleCache implements CacheInterface {
    private static $cache = []; // Usamos static para persistir en la misma solicitud
    public function get(string $key, mixed $default = null): mixed {
        return array_key_exists($key, self::$cache) ? self::$cache[$key] : $default;
    }
    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool {
        self::$cache[$key] = $value;
        return true;
    }
    public function delete(string $key): bool {
        unset(self::$cache[$key]);
        return true;
    }
    public function clear(): bool {
        self::$cache = [];
        return true;
    }
    // Métodos no implementados de la interfaz PSR-16 (Simple Cache)
    public function getMultiple(iterable $keys, mixed $default = null): iterable { return []; }
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool { return true; }
    public function deleteMultiple(iterable $keys): bool { return true; }
    public function has(string $key): bool { return array_key_exists($key, self::$cache); }
}
$cache = new SimpleCache();


// --- FUNCIONES DE UTILIDAD ---

/**
 * Envía una respuesta JSON y termina la ejecución.
 * @param array $data Los datos a enviar como JSON.
 * @param int $statusCode El código de estado HTTP.
 */
function sendResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data);
    exit;
}

/**
 * Valida el ID Token de Firebase de la cabecera Authorization.
 * Retorna los claims decodificados del token si es válido.
 * Detiene la ejecución con un error si el token es inválido o falta.
 */
function validateFirebaseToken() {
    global $cache; // Accede a la caché simple

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    // Verifica si el encabezado Authorization tiene el formato "Bearer <token>"
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        sendResponse(['error' => 'Token de autorización no proporcionado o formato incorrecto.'], 401);
    }

    $idToken = $matches[1]; // Extrae el token

    try {
        // 1. Obtener las claves públicas de Google para verificar el token
        $publicKeys = $cache->get('firebase_public_keys');
        if (!$publicKeys) {
            $client = new Client();
            $response = $client->request('GET', GOOGLE_PUBLIC_KEYS_URL);
            $publicKeys = json_decode($response->getBody()->getContents(), true);

            if (empty($publicKeys)) {
                // Loguea el error internamente si falla la obtención de claves
                error_log("FIREBASE_AUTH_ERROR: No se pudieron obtener las claves públicas de Firebase.");
                sendResponse(['error' => 'Error interno de autenticación. Intenta de nuevo.'], 500);
            }
            // Guarda las claves en caché para futuras solicitudes
            $cache->set('firebase_public_keys', $publicKeys, PUBLIC_KEYS_CACHE_TTL);
        }

        // 2. Decodificar y verificar el token usando las claves públicas
        // La librería JWT necesita las claves como un array donde la clave del array es el 'kid' (key ID)
        $decodedToken = null;
        foreach ($publicKeys as $kid => $publicKey) {
            try {
                // Intenta decodificar con cada clave hasta encontrar la correcta (que coincida con el kid del token)
                // Se asume el algoritmo RS256, estándar para Firebase ID Tokens
                $decodedToken = JWT::decode($idToken, new Key($publicKey, 'RS256'));
                break; // Si se decodificó, salimos del bucle
            } catch (\Exception $e) {
                // Si esta clave no funcionó, intenta con la siguiente
                continue;
            }
        }

        if (is_null($decodedToken)) {
            // Esto ocurre si ninguna de las claves públicas pudo decodificar el token
            sendResponse(['error' => 'Token JWT inválido o firma no reconocida.'], 401);
        }

        // 3. Validar los claims estándar del token (emisor, audiencia, expiración)
        $issuer = 'https://securetoken.google.com/' . FIREBASE_PROJECT_ID;
        if ($decodedToken->iss !== $issuer) {
            sendResponse(['error' => 'Token JWT inválido (emisor incorrecto).'], 401);
        }
        if ($decodedToken->aud !== FIREBASE_PROJECT_ID) {
            sendResponse(['error' => 'Token JWT inválido (audiencia incorrecta).'], 401);
        }
        if ($decodedToken->exp < time()) {
            sendResponse(['error' => 'Token JWT expirado.'], 401);
        }

        return $decodedToken; // Retorna el objeto con los claims decodificados

    } catch (\Firebase\JWT\ExpiredException $e) {
        sendResponse(['error' => 'Token JWT expirado.'], 401);
    } catch (\Firebase\JWT\SignatureInvalidException $e) {
        sendResponse(['error' => 'Firma del token JWT inválida.'], 401);
    } catch (\Firebase\JWT\BeforeValidException $e) {
        sendResponse(['error' => 'Token JWT no válido aún.'], 401);
    } catch (\Exception $e) {
        // Captura cualquier otro error durante la validación del JWT o la solicitud HTTP
        error_log("FIREBASE_AUTH_ERROR: " . $e->getMessage()); // Loguea el error para depuración
        sendResponse(['error' => 'Error de validación del token. Intenta de nuevo.'], 401);
    }
}


/**
 * Autorización: Verifica si el usuario autenticado tiene el rol de administrador.
 * Requiere que hayas configurado un Custom Claim 'admin: true' en Firebase Authentication para tus usuarios admin.
 * @param object $decodedToken El token decodificado con los claims.
 * @return bool True si es administrador, false en caso contrario.
 */
function isUserAdmin($decodedToken) {
    // Los custom claims de Firebase están anidados bajo el claim 'firebase'
    // Asegúrate de que tu claim personalizado 'admin' esté presente y sea true
    return isset($decodedToken->admin) && $decodedToken->admin === true;
}


// --- AUTENTICACIÓN Y AUTORIZACIÓN (Se ejecuta antes de cualquier lógica de API) ---

// Valida el token del usuario. Si es inválido, detiene la ejecución.
$decodedToken = validateFirebaseToken();

// Autorización: Verifica si el usuario autenticado tiene permisos de administrador.
if (!isUserAdmin($decodedToken)) {
    // Si no es admin, denegar acceso a todas las operaciones de gestión de imágenes.
    sendResponse(['error' => 'Acceso denegado. Se requiere rol de administrador.'], 403);
}


// --- LÓGICA DE MANEJO DE IMÁGENES (Ahora protegida) ---

/**
 * Maneja la subida de una nueva imagen.
 */
function handleImageUpload() {
    global $upload_dir_base, $base_url;

    if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        sendResponse(['error' => 'No se subió ningún archivo o hubo un error en la subida.'], 400);
    }

    $file = $_FILES['image'];

    // Validación básica del tipo de archivo (puedes expandir esto)
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($file['type'], $allowedTypes)) {
        sendResponse(['error' => 'Tipo de archivo no permitido. Solo se aceptan JPEG, PNG, GIF, WEBP.'], 400);
    }

    // Validación del tamaño del archivo (ej. máximo 5MB)
    // Puedes ajustar el valor '5 * 1024 * 1024'
    if ($file['size'] > 5 * 1024 * 1024) {
        sendResponse(['error' => 'El archivo es demasiado grande. Tamaño máximo permitido: 5MB.'], 400);
    }

    // Obtener la extensión del archivo
    $fileExtension = pathinfo($file['name'], PATHINFO_EXTENSION);

    // Crear subcarpetas por año y mes
    $year = date('Y');
    $month = date('m');
    $destination_folder = $upload_dir_base . $year . '/' . $month . '/';

    // Asegurarse de que la carpeta de destino exista y sea escribible
    if (!is_dir($destination_folder)) {
        // 0755: Permisos de lectura/escritura/ejecución para el propietario, lectura/ejecución para grupo/otros.
        // true: crea directorios recursivamente.
        if (!mkdir($destination_folder, 0755, true)) {
            sendResponse(['error' => 'No se pudo crear el directorio de destino.'], 500);
        }
    }

    // Generar un nombre de archivo único
    // Usamos uniqid() para una cadena única basada en microsegundos, y agregamos un timestamp para mayor unicidad.
    $uniqueFileName = uniqid('', true) . '_' . time() . '.' . $fileExtension;
    $destination_path = $destination_folder . $uniqueFileName;

    // Mover el archivo subido de la ubicación temporal a la ubicación final
    if (move_uploaded_file($file['tmp_name'], $destination_path)) {
        // Construir la URL completa de la imagen
        $image_url = $base_url . $year . '/' . $month . '/' . $uniqueFileName;
        sendResponse(['message' => 'Imagen subida exitosamente.', 'url' => $image_url, 'filename' => $uniqueFileName], 200);
    } else {
        // Registrar el error para depuración
        error_log("Error al mover el archivo subido: " . $file['tmp_name'] . " a " . $destination_path);
        sendResponse(['error' => 'No se pudo mover el archivo a su destino final.'], 500);
    }
}

/**
 * Maneja la eliminación de una imagen.
 * Espera el nombre del archivo en el cuerpo de la solicitud (form-data).
 */
function handleImageDelete() {
    global $upload_dir_base;

    // Obtener el nombre del archivo del cuerpo de la solicitud POST
    $filename = $_POST['filename'] ?? '';

    if (empty($filename)) {
        sendResponse(['error' => 'Nombre de archivo no proporcionado para eliminar.'], 400);
    }

    // Es crucial sanear el nombre del archivo para evitar ataques de Path Traversal
    // Aquí solo permitimos letras, números, guiones, puntos y barras para las subcarpetas.
    // Un nombre de archivo como "2025/06/mi_imagen.png" es válido.
    if (!preg_match('/^[a-zA-Z0-9_\-.\/]+$/', $filename)) {
        sendResponse(['error' => 'Formato de nombre de archivo inválido.'], 400);
    }

    // Construir la ruta completa del archivo a eliminar
    $file_to_delete = $upload_dir_base . $filename;

    // Asegurarse de que el archivo existe y es realmente un archivo (no un directorio)
    // y que está dentro de la carpeta de subidas para evitar eliminar archivos del sistema.
    if (file_exists($file_to_delete) && is_file($file_to_delete) && str_starts_with(realpath($file_to_delete), realpath($upload_dir_base))) {
        if (unlink($file_to_delete)) {
            sendResponse(['message' => 'Imagen eliminada exitosamente.', 'filename' => $filename], 200);
        } else {
            // Loguea el error de unlink
            error_log("Error al eliminar el archivo: " . $file_to_delete);
            sendResponse(['error' => 'No se pudo eliminar la imagen.'], 500);
        }
    } else {
        sendResponse(['error' => 'Archivo no encontrado o acceso denegado.'], 404);
    }
}

/**
 * Maneja el reemplazo de una imagen existente.
 * Espera el nombre del archivo original a reemplazar y la nueva imagen.
 */
function handleImageReplace() {
    global $upload_dir_base, $base_url;

    $original_filename = $_POST['original_filename'] ?? ''; // Nombre del archivo a reemplazar
    $new_file = $_FILES['image'] ?? null; // La nueva imagen a subir

    if (empty($original_filename) || $new_file['error'] !== UPLOAD_ERR_OK) {
        sendResponse(['error' => 'Faltan datos (nombre de archivo original o nueva imagen no subida).'], 400);
    }

    // Saneamiento y verificación del nombre del archivo original (similar a eliminar)
    if (!preg_match('/^[a-zA-Z0-9_\-.\/]+$/', $original_filename)) {
        sendResponse(['error' => 'Formato de nombre de archivo original inválido.'], 400);
    }

    $original_path = $upload_dir_base . $original_filename;

    if (!file_exists($original_path) || !is_file($original_path) || !str_starts_with(realpath($original_path), realpath($upload_dir_base))) {
        sendResponse(['error' => 'La imagen original no fue encontrada o es inválida.'], 404);
    }

    // Validación de la nueva imagen (tipo y tamaño)
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($new_file['type'], $allowedTypes)) {
        sendResponse(['error' => 'Tipo de nueva imagen no permitido. Solo se aceptan JPEG, PNG, GIF, WEBP.'], 400);
    }
    if ($new_file['size'] > 5 * 1024 * 1024) {
        sendResponse(['error' => 'La nueva imagen es demasiado grande. Tamaño máximo permitido: 5MB.'], 400);
    }

    // Mover la nueva imagen (sobrescribirá la original si los nombres son idénticos)
    // Para asegurar el reemplazo y mantener la URL, usamos el mismo nombre y ruta.
    $new_file_extension = pathinfo($new_file['name'], PATHINFO_EXTENSION);
    $original_file_extension = pathinfo($original_filename, PATHINFO_EXTENSION);

    // Si la extensión de la nueva imagen es diferente, necesitamos manejarlo.
    // Para simplificar, asumiremos que se reemplaza con el mismo nombre y extensión si es posible,
    // o se genera uno nuevo. La opción más simple es sobrescribir el archivo.
    // Si quieres mantener el mismo nombre pero cambiar la extensión, necesitarías renombrar.
    // Por simplicidad, sobrescribiremos directamente.
    $destination_path = $original_path; // Sobrescribe el archivo original

    if (move_uploaded_file($new_file['tmp_name'], $destination_path)) {
        // La URL de la imagen reemplazada es la misma que la original.
        $image_url = $base_url . $original_filename;
        sendResponse(['message' => 'Imagen reemplazada exitosamente.', 'url' => $image_url, 'filename' => $original_filename], 200);
    } else {
        error_log("Error al reemplazar el archivo: " . $new_file['tmp_name'] . " a " . $destination_path);
        sendResponse(['error' => 'No se pudo reemplazar la imagen.'], 500);
    }
}

// --- ENRUTAMIENTO DE LA API ---

$method = $_SERVER['REQUEST_METHOD'];
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path_segments = explode('/', trim($request_uri, '/'));

// La acción (images.php o images si usas reescritura de URL)
$action = end($path_segments); // Obtiene el último segmento de la URL

// Asegurarse de que la ruta base coincida con el endpoint de nuestra API
// Si la URL es /api/images.php o /api/images
if ($action === 'images.php' || $action === 'images') {
    if ($method === 'POST') {
        handleImageUpload();
    } elseif ($method === 'DELETE') {
        handleImageDelete();
    } elseif ($method === 'PUT') {
        handleImageReplace();
    } else {
        sendResponse(['message' => 'Método no soportado para este endpoint.'], 405);
    }
} else {
    // Si la solicitud no es para el endpoint de imágenes (ej. /api/otro_endpoint)
    sendResponse(['message' => 'Endpoint no encontrado.'], 404);
}

?>