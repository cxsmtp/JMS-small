import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Inventory class
 * Focus: SQL Injection vulnerability remediation verification
 *
 * These tests verify that:
 * 1. PreparedStatement is used instead of Statement
 * 2. User input is properly parameterized
 * 3. SQL injection attacks are prevented
 * 4. Normal functionality is preserved
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private JDesktopPane mockDesktop;

    @BeforeEach
    public void setUp() throws Exception {
        inventory = new Inventory();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockDesktop = mock(JDesktopPane.class);

        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    @AfterEach
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
    }

    /**
     * Test 1: Verify PreparedStatement is used for INSERT operation
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testUsesPreparedStatementForInsert() throws Exception {
        // Create the frame to initialize components
        inventory.InventoryFrame(mockDesktop);

        // Set legitimate input values
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("High quality diamonds");

        // Replace connection with mock
        inventory.con = mockConnection;

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement was created with parameterized query
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );
    }

    /**
     * Test 2: Verify SQL injection attack is prevented - Single quote injection
     * Malicious input with SQL injection attempt should be treated as literal data
     */
    @Test
    public void testPreventsBasicSqlInjectionWithSingleQuote() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Attempt SQL injection with single quote
        String maliciousInput = "'; DROP TABLE Inventory; --";
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("Normal details");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is set as a parameter (treated as literal data)
        verify(mockPreparedStatement).setString(1, maliciousInput);

        // Verify the query execution happened (meaning it didn't break out of the query)
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 3: Verify SQL injection with UNION attack is prevented
     */
    @Test
    public void testPreventsUnionBasedSqlInjection() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Attempt UNION-based SQL injection
        String unionAttack = "' UNION SELECT username, password FROM users --";
        inventory.details.setText(unionAttack);
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the attack string is safely parameterized
        verify(mockPreparedStatement).setString(9, unionAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 4: Verify all parameters are correctly bound
     * Ensures no parameter is missed in the remediation
     */
    @Test
    public void testAllParametersAreBoundCorrectly() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Set all fields with distinct values
        inventory.style_id.setText("STYLE_VALUE");
        inventory.Vendor_id.setText("VENDOR_VALUE");
        inventory.in_date.setText("DATE_VALUE");
        inventory.gold_cr.setText("GOLD_CR_VALUE");
        inventory.gold_wt.setText("GOLD_WT_VALUE");
        inventory.stone_type.setText("STONE_TYPE_VALUE");
        inventory.stone_wt.setText("STONE_WT_VALUE");
        inventory.stone_number.setText("STONE_NUM_VALUE");
        inventory.details.setText("DETAILS_VALUE");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all 9 parameters are set in correct order
        verify(mockPreparedStatement).setString(1, "STYLE_VALUE");
        verify(mockPreparedStatement).setString(2, "VENDOR_VALUE");
        verify(mockPreparedStatement).setString(3, "DATE_VALUE");
        verify(mockPreparedStatement).setString(4, "GOLD_CR_VALUE");
        verify(mockPreparedStatement).setString(5, "GOLD_WT_VALUE");
        verify(mockPreparedStatement).setString(6, "STONE_TYPE_VALUE");
        verify(mockPreparedStatement).setString(7, "STONE_WT_VALUE");
        verify(mockPreparedStatement).setString(8, "STONE_NUM_VALUE");
        verify(mockPreparedStatement).setString(9, "DETAILS_VALUE");
    }

    /**
     * Test 5: Verify SQL injection with comment injection is prevented
     */
    @Test
    public void testPreventsCommentInjection() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Attempt comment injection to bypass authentication or conditions
        String commentAttack = "admin' --";
        inventory.Vendor_id.setText(commentAttack);
        inventory.style_id.setText("STY001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("Details");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the comment attack is treated as literal data
        verify(mockPreparedStatement).setString(2, commentAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 6: Verify SQL injection with OR-based attack is prevented
     */
    @Test
    public void testPreventsOrBasedSqlInjection() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Attempt OR-based injection
        String orAttack = "' OR '1'='1";
        inventory.stone_type.setText(orAttack);
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("Details");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the OR attack is safely parameterized
        verify(mockPreparedStatement).setString(6, orAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 7: Verify special characters are handled safely
     * Tests that special SQL characters don't break the query
     */
    @Test
    public void testHandlesSpecialCharactersSafely() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Test various special characters that could cause issues in concatenated SQL
        inventory.style_id.setText("STY'001");
        inventory.Vendor_id.setText("VEN\"002");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Dia;mond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("Details with ' and \" and ; characters");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all special characters are safely handled as parameters
        verify(mockPreparedStatement).setString(1, "STY'001");
        verify(mockPreparedStatement).setString(2, "VEN\"002");
        verify(mockPreparedStatement).setString(6, "Dia;mond");
        verify(mockPreparedStatement).setString(9, "Details with ' and \" and ; characters");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify empty strings are handled correctly
     */
    @Test
    public void testHandlesEmptyStringsSafely() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Set some fields to empty strings
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify empty strings are handled
        verify(mockPreparedStatement).setString(1, "");
        verify(mockPreparedStatement).setString(2, "");
        verify(mockPreparedStatement).setString(9, "");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 9: Verify very long input doesn't cause SQL injection
     */
    @Test
    public void testHandlesLongInputSafely() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Create a very long string with potential SQL injection payload
        String longInput = "A".repeat(1000) + "'; DROP TABLE Inventory; --";

        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");
        inventory.details.setText(longInput);

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify long input is safely parameterized
        verify(mockPreparedStatement).setString(9, longInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 10: Verify stacked queries attack is prevented
     */
    @Test
    public void testPreventsStackedQueriesInjection() throws Exception {
        inventory.InventoryFrame(mockDesktop);

        // Attempt stacked queries injection
        String stackedQueries = "'; DELETE FROM Inventory WHERE '1'='1";
        inventory.details.setText(stackedQueries);
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("20/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("25.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("10");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the stacked query attempt is treated as literal data
        verify(mockPreparedStatement).setString(9, stackedQueries);
        verify(mockPreparedStatement).executeUpdate();
    }
}
