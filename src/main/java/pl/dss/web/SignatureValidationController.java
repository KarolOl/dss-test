package pl.dss.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import pl.dss.validation.SignatureValidationService;
import pl.dss.validation.model.CompositeValidationReport;

import java.util.List;

@RestController
@RequestMapping("/api/signatures")
public class SignatureValidationController {
    private final SignatureValidationService service;

    public SignatureValidationController(SignatureValidationService service) {
        this.service = service;
    }

    @PostMapping(value = "/validate", consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public CompositeValidationReport validate(@RequestPart("file") MultipartFile file,
            @RequestPart(value = "detachedContents", required = false) List<MultipartFile> detachedContents) {
        return service.validate(file, detachedContents);
    }
}
