package paramvalidator

// Security limits for parameter validation
const (
	MaxRulesSize       = 5000  // Reduced from 10000
	MaxParamValues     = 100   // Reduced from 500
	MaxURLLength       = 2048  // Reduced from 4096
	MaxParamNameLength = 128   // Reduced from 256
	MaxPatternLength   = 512   // Reduced from 1024
	MaxParamsCount     = 64    // Reduced from 128
)
