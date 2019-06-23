package net.xdclass.rbac_shiro.config;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import com.alibaba.druid.util.StringUtils;

import net.xdclass.rbac_shiro.domain.Permission;
import net.xdclass.rbac_shiro.domain.Role;
import net.xdclass.rbac_shiro.domain.User;
import net.xdclass.rbac_shiro.service.UserService;

public class CustomRealm extends AuthorizingRealm{

	@Autowired
	private UserService userService;
	
	/**
	 * 用户授权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("授权 doGetAuthorizationInfo");
		//String username = (String)principals.getPrimaryPrincipal();
		//User user = userService.findAllUserInfoByUsername(username);
		//配合redis缓存
		User newUser = (User)principals.getPrimaryPrincipal();
	    User user = userService.findAllUserInfoByUsername(newUser.getUsername());
		List<String> stringRoleList = new ArrayList<>();
		List<String> stringPermissionList = new ArrayList<>();
		
		List<Role> roleList = user.getRoleList();
		
		for(Role role : roleList){
			stringRoleList.add(role.getName());
			List<Permission> permissionList = role.getPermissionList();
			for(Permission permission : permissionList){
				if(permission!=null){
					stringPermissionList.add(permission.getName());
				}
			}
		}
		
		SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
		simpleAuthorizationInfo.addRoles(stringRoleList);
		simpleAuthorizationInfo.addStringPermissions(stringPermissionList);
		
		return simpleAuthorizationInfo;
	}

	/**
	 * 用户认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("认证 doGetAuthenticationInfo");
		//从token中获取用户信息 用户输入的
		String username = (String)token.getPrincipal();
		User user = userService.findAllUserInfoByUsername(username);
		if(user == null){
			return null;
		}
		//取密码
		String pwd = user.getPassword();
		if(StringUtils.isEmpty(pwd)){
			return null;
		}
//		return new SimpleAuthenticationInfo(username,user.getPassword(),this.getClass().getName());
		//配合redis缓存
		return new SimpleAuthenticationInfo(user, user.getPassword(), this.getClass().getName());
	}
}
