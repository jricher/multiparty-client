<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ page session="false" %>
<o:header title="Home"/>
<o:topbar pageName="Home"/>
<div class="container-fluid main">
	<div class="row-fluid">
		<div class="span10 offset1">

			<h1>
				Hello world!
			</h1>
		
			<div>
			
				<form method="POST" action="fetch">
					<input type="text" name="resource" placeholder="resource uri" />
					<input type="submit" value="Fetch" />
				</form>

			</div>				

			<div>
			
			<b>Label:</b> 
			<c:if test="${ not empty label }"><c:out value="${ label }"/></c:if>
			
			</div>
			<div>
			
			<b>Value:</b> 
			<c:if test="${ not empty value }"><c:out value="${ value }"/></c:if>
			
			</div>
		</div>
	</div>
</div>


<o:footer />