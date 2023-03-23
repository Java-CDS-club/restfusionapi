package be.sinube.restfusion.restfusion.controller;

import be.sinube.restfusion.restfusion.JWT.GenerateJWTService;
import be.sinube.restfusion.restfusion.JWT.GenerateJWTThirdPartyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RestFusionController {

    @Autowired
    GenerateJWTService service;

    @Autowired
    GenerateJWTThirdPartyService serviceThirdParty;

    @GetMapping("/getToken")
    public String getToken() throws InterruptedException {
        return service.generateJWT();

    }

    @GetMapping("/getTokenThirdParty")
    public String getTokenThirdParty() throws InterruptedException {
        return serviceThirdParty.generateJWTThirdParty();

    }
}
