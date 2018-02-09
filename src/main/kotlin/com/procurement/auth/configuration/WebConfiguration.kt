package com.procurement.auth.configuration

import org.springframework.boot.web.servlet.ServletComponentScan
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.EnableWebMvc

@Configuration
@EnableWebMvc
@ServletComponentScan(basePackages = ["com.procurement.auth.filter"])
@ComponentScan(basePackages = ["com.procurement.auth.controller"])
class WebConfiguration