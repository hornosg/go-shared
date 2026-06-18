package businesstype

import (
	"strings"
)

// productCategoryRule maps a normalized keyword (lowercase, no accents) to a
// business type code and name. Must stay aligned with categoryToBusinessType in
// webdata-service — same valid codes/names, same taxonomy decisions
// (e.g. lacteos → fiambreria, limpieza → limpieza, supermercado/almacen → almacen).
//
// Keys are single words; matching is done via strings.Contains so a keyword "leche"
// will match both "leches larga vida" and "/Lácteos/Leches/".
// Order matters only within a keyword group when building the result; the lookup
// iterates keywords in declaration order via the slice below.
//
// Promoted from webdata-service/src/product/domain/value_object/product_category_resolver.go
// as part of E24 / ADR-005 §5 — single source of truth for the category→business_type taxonomy.
type productCategoryRule struct {
	keyword          string
	businessTypeCode string
	businessTypeName string
}

// productCategoryRules is evaluated in order. The FIRST rule whose keyword is found
// inside the normalized category wins. Put more specific keywords before broader ones
// when two could match the same string (e.g. "yogur" before "lacteo").
//
// WARNING: THE ORDER OF THIS SLICE IS LOAD-BEARING. Do NOT reorder, sort, or "clean up"
// these entries. Collision guards depend on evaluation order:
//   - "congelado"/"congelados" MUST be first: all "/Congelados/..." goes to congelados,
//     winning over fiambreria/carniceria/verduleria/vino.
//   - "vinagre" before "vino": "Vinagre de manzana" → almacen, not vinoteca.
//   - "conserva" before "carne"/"pollo": "Conservas de carne" → almacen, not carniceria.
//   - "mermelada"/"salsa" before "fruta"/"verdura": "Mermelada de fruta" → almacen, not verduleria.
//   - "yogur" first of all lacteos: "Yogur con frutas" → fiambreria (wins over verduleria).
//   - Specific rubros (panaderia, carniceria, verduleria, veterinaria, vinoteca, libreria,
//     jugueteria, peluqueria, piletas, electricidad) go BEFORE the almacen catch-all block.
var productCategoryRules = []productCategoryRule{
	// --- Congelados (rubro propio) ---
	// MUST be FIRST: decisión del owner = TODO "/Congelados/..." va a congelados,
	// gane sobre fiambreria/carniceria/verduleria/vino (ej. "/Congelados/Helados de
	// crema/" → congelados, no fiambreria; "/Congelados/Pollo/" → congelados, no
	// carniceria). Ningún rubro no-congelado contiene el substring "congelado".
	{keyword: "congelado", businessTypeCode: "congelados", businessTypeName: "Congelados"},
	{keyword: "congelados", businessTypeCode: "congelados", businessTypeName: "Congelados"},

	// --- Fiambrería (taxonomía: lácteos + fiambres/quesos van a fiambrería) ---
	// Must be FIRST so "yogur con frutas" → fiambreria, not verduleria.
	{keyword: "yogur", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "queso", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "fiambre", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "lacteo", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "lacteos", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "leche", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "manteca", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "crema", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},
	{keyword: "margarina", businessTypeCode: "fiambreria", businessTypeName: "Fiambrería y Rotisería"},

	// --- Limpieza ---
	{keyword: "limpieza", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},
	{keyword: "lavandina", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},
	{keyword: "detergente", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},
	{keyword: "cuidado de ropa", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},
	{keyword: "ropa lavado", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},
	{keyword: "suavizante", businessTypeCode: "limpieza", businessTypeName: "Casa de Limpieza"},

	// --- Farmacia ---
	{keyword: "farmacia", businessTypeCode: "farmacia", businessTypeName: "Farmacia"},
	{keyword: "bebe", businessTypeCode: "farmacia", businessTypeName: "Farmacia"},
	{keyword: "bebes", businessTypeCode: "farmacia", businessTypeName: "Farmacia"},
	{keyword: "pañal", businessTypeCode: "farmacia", businessTypeName: "Farmacia"},
	{keyword: "panal", businessTypeCode: "farmacia", businessTypeName: "Farmacia"},

	// --- Perfumería ---
	{keyword: "perfumeria", businessTypeCode: "perfumeria", businessTypeName: "Perfumería"},
	{keyword: "higiene personal", businessTypeCode: "perfumeria", businessTypeName: "Perfumería"},
	{keyword: "cuidado personal", businessTypeCode: "perfumeria", businessTypeName: "Perfumería"},
	{keyword: "shampoo", businessTypeCode: "perfumeria", businessTypeName: "Perfumería"},
	{keyword: "desodorante", businessTypeCode: "perfumeria", businessTypeName: "Perfumería"},

	// --- Ferretería ---
	{keyword: "ferreteria", businessTypeCode: "ferreteria", businessTypeName: "Ferretería y Corralón"},
	{keyword: "construccion", businessTypeCode: "ferreteria", businessTypeName: "Ferretería y Corralón"},
	{keyword: "sanitario", businessTypeCode: "ferreteria", businessTypeName: "Ferretería y Corralón"},

	// --- Casa de Electrodomésticos ---
	{keyword: "electrodomestico", businessTypeCode: "electrodomesticos", businessTypeName: "Electrodomésticos"},
	{keyword: "electronica", businessTypeCode: "electrodomesticos", businessTypeName: "Electrodomésticos"},
	{keyword: "tecnologia", businessTypeCode: "electrodomesticos", businessTypeName: "Electrodomésticos"},

	// --- Electricidad ---
	{keyword: "electricidad", businessTypeCode: "electricidad", businessTypeName: "Electricidad"},
	{keyword: "iluminacion", businessTypeCode: "electricidad", businessTypeName: "Electricidad"},
	// "cable" is intentionally short but distinct enough; padding handles boundary.
	{keyword: " cable ", businessTypeCode: "electricidad", businessTypeName: "Electricidad"},

	// --- Bazar ---
	{keyword: "bazar", businessTypeCode: "bazar", businessTypeName: "Bazar"},

	// --- Tienda de Ropa ---
	{keyword: "indumentaria", businessTypeCode: "ropa", businessTypeName: "Ropa y Calzado"},
	{keyword: "calzado", businessTypeCode: "ropa", businessTypeName: "Ropa y Calzado"},

	// --- Piletas y Jardín ---
	{keyword: "pileta", businessTypeCode: "piletas", businessTypeName: "Piletas y Jardín"},
	{keyword: "jardin", businessTypeCode: "piletas", businessTypeName: "Piletas y Jardín"},

	// --- Peluquería y Estética ---
	{keyword: "peluqueria", businessTypeCode: "peluqueria", businessTypeName: "Peluquería y Estética"},
	{keyword: "estetica", businessTypeCode: "peluqueria", businessTypeName: "Peluquería y Estética"},

	// --- Juguetería ---
	{keyword: "juguete", businessTypeCode: "jugueteria", businessTypeName: "Juguetería"},
	{keyword: "jugueteria", businessTypeCode: "jugueteria", businessTypeName: "Juguetería"},

	// --- Librería y Papelería ---
	{keyword: "libreria", businessTypeCode: "libreria", businessTypeName: "Librería y Papelería"},
	{keyword: "papeleria", businessTypeCode: "libreria", businessTypeName: "Librería y Papelería"},
	{keyword: "cuaderno", businessTypeCode: "libreria", businessTypeName: "Librería y Papelería"},
	{keyword: "lapiz", businessTypeCode: "libreria", businessTypeName: "Librería y Papelería"},

	// --- Almacén catch-all guards (MUST be before carniceria/verduleria/vinoteca rules) ---
	// These prevent content-like subcategories from being mis-classified by the specific
	// rubros below. Order: conserva before carne/pollo; mermelada+salsa before fruta/verdura;
	// vinagre before vino.
	{keyword: "conserva", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "mermelada", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "salsa", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "vinagre", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},

	// --- Carnicería (frescos: carne, pollo, milanesa, bondiola) ---
	// NOTE: "conserva" guard above ensures "Conservas de carne" → almacen, not carniceria.
	{keyword: "carne", businessTypeCode: "carniceria", businessTypeName: "Carnicería"},
	{keyword: "pollo", businessTypeCode: "carniceria", businessTypeName: "Carnicería"},
	{keyword: "milanesa", businessTypeCode: "carniceria", businessTypeName: "Carnicería"},
	{keyword: "bondiola", businessTypeCode: "carniceria", businessTypeName: "Carnicería"},
	{keyword: "carniceria", businessTypeCode: "carniceria", businessTypeName: "Carnicería"},

	// --- Verdulería y Frutería ---
	// NOTE: "mermelada" and "salsa" guards above prevent "Mermelada de fruta" → verduleria.
	{keyword: "verdura", businessTypeCode: "verduleria", businessTypeName: "Verdulería y Frutería"},
	{keyword: "fruta", businessTypeCode: "verduleria", businessTypeName: "Verdulería y Frutería"},
	{keyword: "verduleria", businessTypeCode: "verduleria", businessTypeName: "Verdulería y Frutería"},
	{keyword: "fruteria", businessTypeCode: "verduleria", businessTypeName: "Verdulería y Frutería"},

	// --- Veterinaria y Mascotas ---
	{keyword: "mascota", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},
	{keyword: "veterinaria", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},
	{keyword: "perro", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},
	{keyword: "gato", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},
	{keyword: "balanceado", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},
	{keyword: "alimento para", businessTypeCode: "veterinaria", businessTypeName: "Veterinaria y Mascotas"},

	// --- Panadería y Cafetería (frescos: pan artesanal, factura, etc.) ---
	// "galletita" stays in almacen (packaged, not fresh bakery) — its rule is in the
	// almacen block below, which comes AFTER this section.
	// "pan " with trailing space avoids matching "panificado" or "pantalon".
	{keyword: "pan ", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "panaderia", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "panificado", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "factura", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "bizcochuelo", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "budin", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},
	{keyword: "magdalena", businessTypeCode: "panaderia", businessTypeName: "Panadería y Cafetería"},

	// --- Vinoteca ---
	// NOTE: "vinagre" guard above ensures "Vinagre de manzana" → almacen, not vinoteca.
	// "vino" with boundaries: padded string is " <normalized> " so "vino" matches
	// " vino malbec " but NOT " vinagre " (which was already caught above).
	{keyword: "vino", businessTypeCode: "vinoteca", businessTypeName: "Vinoteca"},
	{keyword: "vinoteca", businessTypeCode: "vinoteca", businessTypeName: "Vinoteca"},
	{keyword: "vinos", businessTypeCode: "vinoteca", businessTypeName: "Vinoteca"},

	// --- Almacén de Barrio (catch-all de alimentos/bebidas/consumo masivo) ---
	// Bebidas
	{keyword: "bebida", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "gaseosa", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "agua", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "jugo", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "cerveza", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	// Desayuno / infusiones
	{keyword: "cafe", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "infusion", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "yerba", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "mate", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "te ", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"}, // trailing space to avoid "tecnologia"
	// Aceites / condimentos
	{keyword: "aceite", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "condimento", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	// Harinas / granos
	{keyword: "harina", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "arroz", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "fideo", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "pasta", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "cereal", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "legumbre", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "azucar", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "sal", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	// Panadería packaged (galletita → almacen, not panaderia — consumo masivo empaquetado)
	{keyword: "galletita", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	// Golosinas / chocolates / snacks
	{keyword: "chocolate", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "golosina", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "alfajor", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "snack", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	// Supermercado / almacen genérico
	{keyword: "almacen", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "supermercado", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
	{keyword: "autoservicio", businessTypeCode: "almacen", businessTypeName: "Almacén de Barrio"},
}

// normalizeProductCategory returns a lowercase, accent-stripped, trimmed version
// of the raw category string. Path-style categories like "/Lácteos/Yogures/Yogur en vasos/"
// have their slashes replaced with spaces so keyword matching works across all segments.
func normalizeProductCategory(raw string) string {
	// Replace path separators with spaces so all segments are searchable.
	s := strings.ReplaceAll(raw, "/", " ")
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = stripProductAccents(s)
	return s
}

// stripProductAccents replaces common Spanish accented characters with ASCII.
// Deliberately kept local to this package to avoid coupling with external utilities.
func stripProductAccents(s string) string {
	r := strings.NewReplacer(
		"á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u",
		"ü", "u", "ñ", "n",
		"Á", "a", "É", "e", "Í", "i", "Ó", "o", "Ú", "u",
		"Ü", "u", "Ñ", "n",
	)
	return r.Replace(s)
}

// ResolveBusinessTypeFromProductCategory resolves the business type for an individual
// product's raw category string (e.g. "Cafés", "/Lácteos/Yogures/Yogur en vasos/",
// "LIMPIEZA"). It normalizes the input and matches against productCategoryRules.
//
// Returns (assignment, true) when a match is found, (zero, false) otherwise.
// Callers should fall back to the source-level autoAssignment when this returns false.
//
// WARNING: the order of productCategoryRules is load-bearing — see the slice declaration
// for collision guards. Do NOT reorder the rules without updating the tests in resolver_test.go.
func ResolveBusinessTypeFromProductCategory(rawCategory string) (BusinessTypeAssignment, bool) {
	if rawCategory == "" {
		return BusinessTypeAssignment{}, false
	}

	normalized := normalizeProductCategory(rawCategory)
	if normalized == "" {
		return BusinessTypeAssignment{}, false
	}

	// Pad with a leading and trailing space so boundary-sensitive keywords
	// like "te " and "pan " can match at start-of-string or segment boundaries
	// without false positives inside longer words.
	padded := " " + normalized + " "

	for _, rule := range productCategoryRules {
		if strings.Contains(padded, rule.keyword) {
			assignment, err := NewBusinessTypeAssignment(rule.businessTypeCode, rule.businessTypeName)
			if err != nil {
				return BusinessTypeAssignment{}, false
			}
			return assignment, true
		}
	}

	return BusinessTypeAssignment{}, false
}
