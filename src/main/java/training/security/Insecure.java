package training.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.logging.Logger;

public class Insecure {
  
	private static final Logger LOGGER = Logger.getLogger(Insecure.class.getName());
   
   public void badFunction(HttpServletRequest request) throws IOException {
	  
	
    String obj = request.getParameter("data");
    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();
    File tempDir;
    Path tempPath = Files.createTempDirectory("");
    tempDir = tempPath.toFile();
    
    Files.delete(tempPath);
   	tempDir.mkdir();
    Files.exists(Paths.get("/tmp/", obj));
    
  }

  public String taintedSQL(HttpServletRequest request, Connection connection)  {
    String user = request.getParameter("user");
    
    String query = "SELECT userid FROM users WHERE username = ?";
    String userId =null;
    PreparedStatement pstmt = null;
    ResultSet resultSet = null;
    try {
    	pstmt = connection.prepareStatement(query);
    	pstmt.setString(1,user);
    	resultSet = pstmt.executeQuery();
    	userId = resultSet.getString(1);
        
    }catch(SQLException ex) {
    	LOGGER.severe(ex.toString());
    }finally {
    	closeResoruces(pstmt,resultSet,connection);
    }
    
    
    return userId;
  }
  
  public String hotspotSQL(Connection connection, String user)   {
	  PreparedStatement pstmt = null;
	  ResultSet rs = null;
	  String query = "select userid from users WHERE username= ? ";
	  String userId = null;
	  try {
		  pstmt = connection.prepareStatement(query);
		  pstmt.setString(1, user);
		  rs = pstmt.executeQuery();
		  userId = rs.getString(1);
	  }catch(SQLException sqlEx) {
		  LOGGER.severe(sqlEx.toString());
	  }finally {
		  closeResoruces(pstmt,rs,connection);
	  }
	  
	  return userId;
	  
	  
	}

  private void closeResoruces(PreparedStatement stmt,ResultSet rs, Connection connection) {
		  try {
	    		 if (rs!=null)
	    			 rs.close();
	    	 } catch (Exception e) {
	    		 LOGGER.severe(e.toString());	 
	    	 }
	    	 
	    	 try { 
	    		 if (stmt != null)
	    			 stmt.close();
	    	 } catch (Exception e) {
	    		 LOGGER.severe(e.toString());
	    	 }
	    	
	    	 try { 
	    		connection.close();
	    	 } catch (Exception e) {
	    		 LOGGER.severe(e.toString());
	    	 }
  }

  public void modResponse(HttpServletResponse response) {
    Cookie c = new Cookie("SECRET", "SECRET");
    response.addCookie(c);
  }

  public KeyPair weakKey() {
    KeyPairGenerator keyPairGen;
    try {
      keyPairGen = KeyPairGenerator.getInstance("RSA");
      keyPairGen.initialize(2048);
      return keyPairGen.genKeyPair();
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }

  // --------------------------------------------------------------------------
  // Custom sources, sanitizer and sinks example
  // See file s3649JavaSqlInjectionConfig.json in root directory 
  // --------------------------------------------------------------------------

  public String getInput(String name) {
    // Empty (fake) source
    // To be a real source this should normally return something from an input
    // that can be user manipulated e.g. an HTTP request, a cmd line parameter, a form input...
    return "Hello World and " + name;
  }

  public void storeData(String input) {
    // Empty (fake) sink
    // To be a real sink this should normally build an SQL query from the input parameter
  }

  public void verifyData(String input) {
    // Empty (fake) sanitizer (sic)
    // To be a real sanitizer this should normally examine the input and sanitize it
    // for any attempt of user manipulation (eg escaping characters, quoting strings etc...)
  }

  public void processParam(String input) {
    // Empty method just for testing
  }

  public void doSomething() {
    String myInput = getInput("Olivier"); // Get data from a source
    processParam(myInput);
    storeData(myInput);                   // store data w/o sanitizing --> Injection vulnerability 
  }

  public void doSomethingSanitized() {
    String myInput = getInput("Cameron"); // Get data from a source
    verifyData(myInput);                  // Sanitize data
    processParam(myInput);
    storeData(myInput);                   // store data after sanitizing --> No injection vulnerability 
  }
}
