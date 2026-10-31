package pl.dss.config;

import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/** The same DSS XML policy implementation, with the exact input captured at startup for audit export. */
public final class ArchivedValidationPolicy extends EtsiValidationPolicy {
    private final byte[] xml;

    private ArchivedValidationPolicy(ConstraintsParameters constraints, byte[] xml) {
        super(constraints);
        this.xml = xml.clone();
    }

    public static ArchivedValidationPolicy load(InputStream input) throws IOException {
        byte[] bytes = input.readAllBytes();
        try (var snapshot = new ByteArrayInputStream(bytes)) {
            // Identical unmarshalling to ValidationPolicyFacade.getValidationPolicy(InputStream).
            return new ArchivedValidationPolicy(ValidationPolicyFacade.newFacade().unmarshall(snapshot), bytes);
        } catch (JAXBException | XMLStreamException | SAXException exception) {
            throw new IOException("Cannot load and archive DSS XML validation policy", exception);
        }
    }

    public static ArchivedValidationPolicy loadDefault() throws IOException {
        // Default path used by EtsiValidationPolicyFactory in DSS 6.5.
        try (InputStream input = EtsiValidationPolicy.class.getResourceAsStream("/policy/constraint.xml")) {
            if (input == null) throw new IOException("DSS default XML validation policy is missing");
            return load(input);
        }
    }

    public byte[] xml() {
        return xml.clone();
    }
}
