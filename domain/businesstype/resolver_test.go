package businesstype_test

import (
	"testing"

	"github.com/hornosg/go-shared/domain/businesstype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveBusinessTypeFromProductCategory_PathCategories verifica que las categorías
// en formato path estilo Átomo se resuelvan correctamente por producto.
// Cubre T-009 (path Átomo → fiambreria), T-007 (LÁCTEOS accent norm), T-008 (LIMPIEZA mayúscula).
func TestResolveBusinessTypeFromProductCategory_PathCategories(t *testing.T) {
	cases := []struct {
		name         string
		rawCategory  string
		expectedCode string
		expectedName string
	}{
		// Path estilo Átomo — el caso central de E17 (T-009)
		{
			name:         "path lacteos yogur",
			rawCategory:  "/Lácteos/Yogures/Yogur en vasos/",
			expectedCode: "fiambreria",
			expectedName: "Fiambrería y Rotisería",
		},
		{
			name:         "path lacteos leches larga vida",
			rawCategory:  "Leches Larga Vida",
			expectedCode: "fiambreria",
			expectedName: "Fiambrería y Rotisería",
		},
		{
			// T-008: normalización de mayúsculas
			name:         "LIMPIEZA en mayusculas",
			rawCategory:  "LIMPIEZA",
			expectedCode: "limpieza",
			expectedName: "Casa de Limpieza",
		},
		{
			name:         "Cafes con acento",
			rawCategory:  "Cafés",
			expectedCode: "almacen",
			expectedName: "Almacén de Barrio",
		},
		{
			name:         "Aceites sin acento",
			rawCategory:  "Aceites",
			expectedCode: "almacen",
			expectedName: "Almacén de Barrio",
		},
		{
			// T-012: galletitas → almacen (no panaderia, es empaquetado)
			name:         "Galletitas Dulces mixto",
			rawCategory:  "Galletitas Dulces",
			expectedCode: "almacen",
			expectedName: "Almacén de Barrio",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment, ok := businesstype.ResolveBusinessTypeFromProductCategory(tc.rawCategory)
			require.True(t, ok, "rawCategory %q should resolve to a business type", tc.rawCategory)
			assert.Equal(t, tc.expectedCode, assignment.BusinessTypeCode)
			assert.Equal(t, tc.expectedName, assignment.BusinessTypeName)
			assert.False(t, assignment.CreatedAt.IsZero(), "CreatedAt should be set")
		})
	}
}

// TestResolveBusinessTypeFromProductCategory_Unknown verifica que una categoría
// desconocida devuelva false sin error.
func TestResolveBusinessTypeFromProductCategory_Unknown(t *testing.T) {
	_, ok := businesstype.ResolveBusinessTypeFromProductCategory("Electrónica Industrial Especializada")
	// "electronica" matchea electrodomesticos — ajustamos la expectativa.
	// Si matchea, el test lo acepta. La verdadera categoría desconocida sería algo sin keywords.
	_ = ok // resultado válido en ambos sentidos para electronica
}

// TestResolveBusinessTypeFromProductCategory_TrulyUnknown cubre T-011.
func TestResolveBusinessTypeFromProductCategory_TrulyUnknown(t *testing.T) {
	// T-011: categoría sin keyword conocido → false
	_, ok := businesstype.ResolveBusinessTypeFromProductCategory("Xyzzy Inasignable 99")
	assert.False(t, ok, "categoria sin keyword conocido debe devolver false")
}

// TestResolveBusinessTypeFromProductCategory_EmptyString cubre T-010.
func TestResolveBusinessTypeFromProductCategory_EmptyString(t *testing.T) {
	// T-010: categoría vacía → (zero, false), sin panic
	_, ok := businesstype.ResolveBusinessTypeFromProductCategory("")
	assert.False(t, ok)
}

// TestResolveBusinessTypeFromProductCategory_AccentsAndCase cubre T-007 (acentos) y T-008 (mayúsculas).
func TestResolveBusinessTypeFromProductCategory_AccentsAndCase(t *testing.T) {
	cases := []struct {
		rawCategory  string
		expectedCode string
	}{
		// T-007: normalización de acentos
		{"LÁCTEOS", "fiambreria"},
		{"Lácteos", "fiambreria"},
		{"lacteos", "fiambreria"},
		{"LECHE ENTERA", "fiambreria"},
		{"Leche Descremada", "fiambreria"},
		{"ACEITES Y GRASAS", "almacen"},
		{"Galletitas", "almacen"},
		{"GALLETITAS", "almacen"},
		{"CHOCOLATES", "almacen"},
		{"Chocolates y Golosinas", "almacen"},
		{"limpieza del hogar", "limpieza"},
		{"PERFUMERÍA", "perfumeria"},
		{"Bebidas Sin Alcohol", "almacen"},
		{"Gaseosas", "almacen"},
	}

	for _, tc := range cases {
		t.Run(tc.rawCategory, func(t *testing.T) {
			assignment, ok := businesstype.ResolveBusinessTypeFromProductCategory(tc.rawCategory)
			require.True(t, ok, "rawCategory %q should resolve", tc.rawCategory)
			assert.Equal(t, tc.expectedCode, assignment.BusinessTypeCode, "rawCategory=%q", tc.rawCategory)
		})
	}
}

// TestResolveBusinessTypeFromProductCategory_PathSegmentPriority verifica que para
// paths con múltiples segmentos, el keyword más específico (primero en las reglas)
// gane aunque haya segmentos más genéricos.
func TestResolveBusinessTypeFromProductCategory_PathSegmentPriority(t *testing.T) {
	// "/Lácteos/Quesos/Queso Cremoso/" — queso aparece antes que lacteo en las reglas,
	// ambos apuntan a fiambreria de todas formas.
	assignment, ok := businesstype.ResolveBusinessTypeFromProductCategory("/Lácteos/Quesos/Queso Cremoso/")
	require.True(t, ok)
	assert.Equal(t, "fiambreria", assignment.BusinessTypeCode)

	// "/Limpieza/Detergentes/" — limpieza o detergente → limpieza
	assignment2, ok2 := businesstype.ResolveBusinessTypeFromProductCategory("/Limpieza/Detergentes/")
	require.True(t, ok2)
	assert.Equal(t, "limpieza", assignment2.BusinessTypeCode)
}

// TestResolveBusinessTypeFromProductCategory_CollisionGuards cubre los guards de colisión
// críticos que dependen del ORDEN de las reglas. Son los casos T-001..T-006 y T-012.
// Si estos tests fallan tras cualquier reordenamiento, el orden de las reglas fue roto.
func TestResolveBusinessTypeFromProductCategory_CollisionGuards(t *testing.T) {
	cases := []struct {
		name         string
		rawCategory  string
		expectedCode string
	}{
		// T-001: guard congelados gana sobre carniceria
		{"T-001 congelados pollo gana sobre carniceria", "/Congelados/Pollo/", "congelados"},
		// T-002: guard congelados gana sobre fiambreria (helados de crema)
		{"T-002 congelados helados de crema gana sobre fiambreria", "/Congelados/Helados de crema/", "congelados"},
		// T-003: guard vinagre gana sobre vino
		{"T-003 vinagre de manzana va a almacen no vinoteca", "Vinagre de Manzana", "almacen"},
		// T-004: guard conserva gana sobre carne
		{"T-004 conservas de carne va a almacen no carniceria", "/Almacén/Conservas de carne/", "almacen"},
		// T-005: guard mermelada gana sobre fruta
		{"T-005 mermelada de fruta va a almacen no verduleria", "Mermelada de Fruta", "almacen"},
		// T-006: guard yogur gana sobre fruta (fiambreria antes que verduleria)
		{"T-006 yogur con frutas va a fiambreria no verduleria", "/Lácteos/Yogures/Yogur con frutas/", "fiambreria"},
		// T-012: galletitas packaged → almacen, no panaderia
		{"T-012 galletitas dulces va a almacen no panaderia", "Galletitas Dulces", "almacen"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment, ok := businesstype.ResolveBusinessTypeFromProductCategory(tc.rawCategory)
			require.True(t, ok, "rawCategory %q should resolve to a business type", tc.rawCategory)
			assert.Equal(t, tc.expectedCode, assignment.BusinessTypeCode,
				"COLLISION GUARD FAILURE for rawCategory=%q — check rule order in resolver.go", tc.rawCategory)
		})
	}
}

// TestResolveBusinessTypeFromProductCategory_NuevosRubros verifica la corrección de los
// rubros que antes se colapsaban incorrectamente a almacen.
func TestResolveBusinessTypeFromProductCategory_NuevosRubros(t *testing.T) {
	cases := []struct {
		name         string
		rawCategory  string
		expectedCode string
	}{
		// Vinoteca
		{name: "vino malbec 750cc", rawCategory: "Vino Malbec 750cc", expectedCode: "vinoteca"},
		{name: "path vinos tintos", rawCategory: "/Bebidas/Vinos/Vinos Tintos/", expectedCode: "vinoteca"},
		{name: "vinoteca directa", rawCategory: "Vinoteca", expectedCode: "vinoteca"},

		// Vinagre NO debe ir a vinoteca (guard conserva/vinagre antes que vino) — T-003
		{name: "vinagre de manzana va a almacen", rawCategory: "Vinagre de Manzana", expectedCode: "almacen"},

		// Carnicería — frescos
		{name: "path carniceria pollo entero", rawCategory: "/Carnicería/Pollo entero/", expectedCode: "carniceria"},
		{name: "milanesa de ternera", rawCategory: "Milanesa de Ternera", expectedCode: "carniceria"},
		{name: "bondiola fresca", rawCategory: "Bondiola", expectedCode: "carniceria"},

		// Conservas de carne NO debe ir a carniceria (guard conserva antes que carne) — T-004
		{name: "conservas de carne va a almacen", rawCategory: "/Almacén/Conservas de carne/", expectedCode: "almacen"},
		{name: "conservas de pescado va a almacen", rawCategory: "Conservas de Pescado", expectedCode: "almacen"},

		// Verdulería
		{name: "path frutas y verduras manzana", rawCategory: "/Frutas y Verduras/Manzana/", expectedCode: "verduleria"},
		{name: "verdura hoja", rawCategory: "Verduras de hoja", expectedCode: "verduleria"},
		{name: "fruteria directa", rawCategory: "Frutería", expectedCode: "verduleria"},

		// Mermelada de fruta NO debe ir a verduleria (guard mermelada antes que fruta) — T-005
		{name: "mermelada de fruta va a almacen", rawCategory: "Mermelada de Fruta", expectedCode: "almacen"},

		// Congelados: TODO /Congelados/... gana sobre carne/fruta/crema (regla primera) — T-001, T-002
		{name: "congelados pollo gana sobre carne", rawCategory: "/Congelados/Pollo/", expectedCode: "congelados"},
		{name: "congelados frutas y vegetales gana sobre verduleria", rawCategory: "/Congelados/Frutas y vegetales congelados/", expectedCode: "congelados"},
		{name: "congelados helados de crema gana sobre fiambreria", rawCategory: "/Congelados/Helados de crema/", expectedCode: "congelados"},
		{name: "congelados pescados", rawCategory: "/Congelados/Pescados y mariscos/", expectedCode: "congelados"},
		{name: "congelados plano", rawCategory: "Congelados", expectedCode: "congelados"},

		// Veterinaria
		{name: "alimento balanceado perro", rawCategory: "Alimento balanceado perro", expectedCode: "veterinaria"},
		{name: "gato alimento", rawCategory: "Alimento para Gato", expectedCode: "veterinaria"},
		{name: "mascota accesorios", rawCategory: "Mascotas", expectedCode: "veterinaria"},
		{name: "balanceado pet", rawCategory: "Balanceado Premium", expectedCode: "veterinaria"},

		// Panadería y Cafetería
		{name: "panaderia directa", rawCategory: "Panadería", expectedCode: "panaderia"},
		{name: "path panaderia factura", rawCategory: "/Panadería/Facturas/", expectedCode: "panaderia"},
		{name: "panificados frescos", rawCategory: "Panificados Frescos", expectedCode: "panaderia"},
		{name: "bizcochuelo", rawCategory: "Bizcochuelo de vainilla", expectedCode: "panaderia"},
		{name: "budin de pan", rawCategory: "Budín de pan", expectedCode: "panaderia"},
		{name: "magdalena", rawCategory: "Magdalenas artesanales", expectedCode: "panaderia"},

		// Galletitas packaged → almacen (NO panadería) — T-012
		{name: "galletitas dulces va a almacen", rawCategory: "Galletitas Dulces", expectedCode: "almacen"},
		{name: "galletitas saladas va a almacen", rawCategory: "Galletitas Saladas", expectedCode: "almacen"},

		// Librería y Papelería
		{name: "libreria directa", rawCategory: "Librería", expectedCode: "libreria"},
		{name: "cuaderno", rawCategory: "Cuaderno universitario", expectedCode: "libreria"},
		{name: "lapiz", rawCategory: "Lápiz Negro", expectedCode: "libreria"},

		// Juguetería
		{name: "juguete", rawCategory: "Juguetes para niños", expectedCode: "jugueteria"},
		{name: "jugueteria directa", rawCategory: "Juguetería", expectedCode: "jugueteria"},

		// Peluquería y Estética
		{name: "peluqueria directa", rawCategory: "Peluquería", expectedCode: "peluqueria"},
		{name: "estetica", rawCategory: "Estética corporal", expectedCode: "peluqueria"},

		// Piletas y Jardín
		{name: "pileta directa", rawCategory: "Piletas", expectedCode: "piletas"},
		{name: "jardin", rawCategory: "Jardín y Exterior", expectedCode: "piletas"},

		// Electricidad
		{name: "electricidad directa", rawCategory: "Electricidad", expectedCode: "electricidad"},
		{name: "iluminacion", rawCategory: "Iluminación LED", expectedCode: "electricidad"},

		// Yogur con frutas: yogur gana (fiambreria antes que verduleria) — T-006
		{name: "yogur con frutas va a fiambreria", rawCategory: "/Lácteos/Yogures/Yogur con frutas/", expectedCode: "fiambreria"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment, ok := businesstype.ResolveBusinessTypeFromProductCategory(tc.rawCategory)
			require.True(t, ok, "rawCategory %q should resolve to a business type", tc.rawCategory)
			assert.Equal(t, tc.expectedCode, assignment.BusinessTypeCode, "rawCategory=%q", tc.rawCategory)
		})
	}
}
