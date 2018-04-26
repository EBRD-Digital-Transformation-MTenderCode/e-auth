package com.procurement.auth.controller

import com.procurement.auth.AUTHORIZATION_HEADER_DESCRIPTION
import com.procurement.auth.WWW_AUTHENTICATE_HEADER_DESCRIPTION
import com.procurement.auth.model.AUTHORIZATION_HEADER_NAME
import com.procurement.auth.model.WWW_AUTHENTICATE_HEADER_NAME
import org.springframework.restdocs.constraints.ConstraintDescriptions
import org.springframework.restdocs.headers.HeaderDocumentation
import org.springframework.restdocs.payload.FieldDescriptor
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.snippet.Attributes.key
import java.util.*

object ModelDescription {
    private const val SUCCESS_DESCRIPTION =
        "The attribute 'success' contains the value 'true' if the operation was successful, otherwise is 'false'."

    object SignIn {
        fun responseSuccessful(): List<FieldDescriptor> {
            return listOf(
                getFieldDescriptor("success", SUCCESS_DESCRIPTION),
                getFieldDescriptor("data", "The data of response."),
                getFieldDescriptor("data.tokens", "The object contains an access token and a refresh token."),
                getFieldDescriptor("data.tokens.access", "The access token."),
                getFieldDescriptor("data.tokens.refresh", "The refresh token.")
            )
        }
    }

    object Refresh {
        fun responseSuccessful(): List<FieldDescriptor> {
            return listOf(
                getFieldDescriptor("success", SUCCESS_DESCRIPTION),
                getFieldDescriptor("data", "The data of response."),
                getFieldDescriptor("data.tokens", "The object contains an access token and a refresh token."),
                getFieldDescriptor("data.tokens.access", "The access token."),
                getFieldDescriptor("data.tokens.refresh", "The refresh token.")
            )
        }
    }

    object Verification {
        fun responseSuccessful(): List<FieldDescriptor> {
            return listOf(
                getFieldDescriptor("success", SUCCESS_DESCRIPTION)
            )
        }
    }

    fun responseError(): List<FieldDescriptor> {
        return listOf(
            getFieldDescriptor("success", SUCCESS_DESCRIPTION),
            getFieldDescriptor("errors", "List of errors."),
            getFieldDescriptor("errors[].code", "The code of the error."),
            getFieldDescriptor("errors[].description", "The description of the error.")
        )
    }

    fun authHeader() = HeaderDocumentation.headerWithName(AUTHORIZATION_HEADER_NAME)
        .description(AUTHORIZATION_HEADER_DESCRIPTION)

    fun wwwAuthHeader(value: String) = HeaderDocumentation.headerWithName(WWW_AUTHENTICATE_HEADER_NAME)
        .description(WWW_AUTHENTICATE_HEADER_DESCRIPTION)
        .attributes(
            key("value")
                .value(value)
        )
}

private fun getFieldDescriptor(
    property: String,
    description: String,
    constraint: ConstraintDescriptions
): FieldDescriptor {
    return fieldWithPath(property)
        .description(formattingDescription(description))
        .attributes(
            key("constraints")
                .value(getConstraints(constraint, property))
        )
}

private fun getFieldDescriptor(property: String, description: String): FieldDescriptor {
    return fieldWithPath(property).description(description)
}

private fun formattingDescription(description: String): String {
    val text = description.trim { it <= ' ' }
    return if (text.endsWith(".")) text else "$text."
}

private fun getConstraints(constraint: ConstraintDescriptions, property: String): String {
    val descriptions = constraint.descriptionsForProperty(property)
    return if (descriptions.isEmpty()) {
        ""
    } else {
        val stringJoiner = StringJoiner(".\n", "", ".")
        descriptions.forEach { stringJoiner.add(it) }
        stringJoiner.toString()
    }
}