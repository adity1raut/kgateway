package tls

import envoycorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

// DataSourceGenerator returns a function that creates Envoy data sources
func DataSourceGenerator(inline bool) func(string) *envoycorev3.DataSource {
	if !inline {
		return func(s string) *envoycorev3.DataSource {
			return &envoycorev3.DataSource{
				Specifier: &envoycorev3.DataSource_Filename{
					Filename: s,
				},
			}
		}
	}

	return func(s string) *envoycorev3.DataSource {
		return &envoycorev3.DataSource{
			Specifier: &envoycorev3.DataSource_InlineString{
				InlineString: s,
			},
		}
	}
}

// CreateInlineDataSource creates an inline string data source
func CreateInlineDataSource(data string) *envoycorev3.DataSource {
	return &envoycorev3.DataSource{
		Specifier: &envoycorev3.DataSource_InlineString{
			InlineString: data,
		},
	}
}