package pl.dss.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pl.dss.config.ArchivedValidationPolicy;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ArchivedValidationPolicyTest {
    @TempDir
    Path directory;

    @Test
    void retainsTheExactPolicyUsedAtStartupEvenWhenItsSourceFileChanges() throws Exception {
        byte[] expected = ArchivedValidationPolicy.loadDefault().xml();
        Path source = directory.resolve("policy.xml");
        Files.write(source, expected);
        ArchivedValidationPolicy policy;
        try (var input = Files.newInputStream(source)) {
            policy = ArchivedValidationPolicy.load(input);
        }

        Files.writeString(source, "A different configuration after application startup");

        assertArrayEquals(expected, policy.xml());
        assertEquals(ArchivedValidationPolicy.loadDefault().getPolicyName(), policy.getPolicyName());
        byte[] exported = policy.xml();
        exported[0] ^= 1;
        assertArrayEquals(expected, policy.xml(), "Exporting evidence must not let a caller change the archive");
    }
}
