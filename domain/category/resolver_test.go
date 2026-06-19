package category

import "testing"

func TestResolveCategorySlug(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantSlug  string
		wantMatch bool
	}{
		// Empty / whitespace -> caller assigns Unclassified
		{"empty", "", "", false},
		{"whitespace", "   ", "", false},

		// EN constants (MercadoLibre) via dictionary
		{"en beers", "BEERS", "cervezas-vinos", true},
		{"en wines", "WINES", "vinos-tintos", true},
		{"en soft drinks", "SOFT_DRINKS", "gaseosas-aguas", true},
		{"en milk", "MILK", "lacteos", true},
		{"en cookies", "COOKIES", "galletitas-dulces", true},
		{"en candies", "CANDIES", "golosinas", true},
		{"en rice", "RICE", "arroz-legumbres", true},
		{"en toilet papers", "TOILET_PAPERS", "papel-higiene", true},
		{"en diapers", "DISPOSABLE_BABY_DIAPERS", "panales", true},

		// Unknown EN constant -> slugified (override territory)
		{"en unknown", "CAKE_TOPPERS", "cake-toppers", true},

		// VTEX paths -> slugified leaf segment
		{"vtex vinos tintos", "/Bebidas/Vinos/Vinos tintos/", "vinos-tintos", true},
		{"vtex galletitas dulces", "/Desayuno y merienda/Galletitas bizcochitos y tostadas/Galletitas dulces/", "galletitas-dulces", true},

		// VTEX paths with a curated alias -> declared slug
		{"alias cervezas", "/Bebidas/Cervezas/", "cervezas-vinos", true},
		{"alias congelados leaf->path", "/Congelados/Helados Y Postres/", "/Congelados/Helados y postres/", true},
		{"alias yogures->lacteos", "/Lácteos y productos frescos/Yogures/Yogures enteros/", "lacteos", true},

		// Uppercase single word
		{"upper bebidas", "BEBIDAS", "bebidas", true},

		// Already-kebab passes through unchanged
		{"kebab passthrough", "vinos-tintos", "vinos-tintos", true},

		// Plain word with accents
		{"word accents", "Cafés", "cafes", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSlug, gotMatch := ResolveCategorySlug(tt.raw)
			if gotSlug != tt.wantSlug || gotMatch != tt.wantMatch {
				t.Errorf("ResolveCategorySlug(%q) = (%q, %v), want (%q, %v)",
					tt.raw, gotSlug, gotMatch, tt.wantSlug, tt.wantMatch)
			}
		})
	}
}

// Determinism: same input always yields the same output.
func TestResolveCategorySlug_Deterministic(t *testing.T) {
	inputs := []string{"BEERS", "/Bebidas/Vinos/Vinos tintos/", "BEBIDAS", "Cafés"}
	for _, in := range inputs {
		first, _ := ResolveCategorySlug(in)
		for i := 0; i < 5; i++ {
			got, _ := ResolveCategorySlug(in)
			if got != first {
				t.Errorf("non-deterministic for %q: %q != %q", in, got, first)
			}
		}
	}
}

func TestSlugify(t *testing.T) {
	tests := map[string]string{
		"Vinos tintos":      "vinos-tintos",
		"Galletitas dulces": "galletitas-dulces",
		"BEBIDAS":           "bebidas",
		"  Mixed  Spaces  ": "mixed-spaces",
		"Pañales/Bebé":      "panales-bebe",
	}
	for in, want := range tests {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
