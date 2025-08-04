package utils

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

func FormatValidationErrors(err error) []string {
	var errors []string

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			errors = append(errors, formatValidationError(e))
		}
	} else {
		errors = append(errors, err.Error())
	}

	return errors
}

func formatValidationError(err validator.FieldError) string {
	field := strings.ToLower(err.Field())

	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, err.Param())
	case "max":
		return fmt.Sprintf("%s must be no more than %s characters long", field, err.Param())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, err.Param())
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}
