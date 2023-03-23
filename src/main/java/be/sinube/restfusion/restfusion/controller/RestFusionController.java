package be.sinube.restfusion.restfusion.controller;

import be.sinube.restfusion.restfusion.JWT.GenerateJWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RestFusionController {

    @Autowired
    GenerateJWTService service;

    @GetMapping("/getToken")
    public String processMatchsheets() throws InterruptedException {
        return service.generateJWT();

    }
}
