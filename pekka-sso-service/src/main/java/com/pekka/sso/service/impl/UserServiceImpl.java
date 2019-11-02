package com.pekka.sso.service.impl;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import com.pekka.common.pojo.PekkaResult;
import com.pekka.common.util.JsonUtils;
import com.pekka.jedis.JedisClient;
import com.pekka.mapper.TbUserMapper;
import com.pekka.pojo.TbUser;
import com.pekka.pojo.TbUserExample;
import com.pekka.pojo.TbUserExample.Criteria;
import com.pekka.sso.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private TbUserMapper userMapper;
	@Autowired
	private JedisClient jedisClient;
	@Value("${USER_SESSION}")
	private String USER_SESSION;
	@Value("${SESSION_EXPIRE}")
	private Integer SESSION_EXPIRE;

	/**
	 * 检查数据是否可用
	 * 
	 * @param data
	 *            待检查的数据
	 * @param type
	 *            数据类型 1:用户名 2:手机号 3:邮箱
	 * @return
	 */
	@Override
	public PekkaResult checkData(String data, int type) {
		TbUserExample example = new TbUserExample();
		Criteria criteria = example.createCriteria();
		// 设置查询条件
		// 1.判断用户名是否可用
		if (type == 1) {
			criteria.andUsernameEqualTo(data);
			// 2.判断手机号是否可用
		} else if (type == 2) {
			criteria.andPhoneEqualTo(data);
			// 3.判断邮箱是否可用
		} else if (type == 3) {
			criteria.andEmailEqualTo(data);
		} else {
			return PekkaResult.build(400, "非法数据");
		}
		List<TbUser> list = userMapper.selectByExample(example);
		if (list != null && list.size() > 0) {
			// 查询到数据，返回false
			return PekkaResult.ok(false);
		}
		// 数据可以使用
		return PekkaResult.ok(true);
	}

	/**
	 * 注册service
	 * 
	 * @param user
	 *            注册的用户
	 * @return
	 */
	@Override
	public PekkaResult register(TbUser user) {
		// 检查数据的有效性
		// 判断用户名是否为空
		if (StringUtils.isBlank(user.getUsername())) {
			return PekkaResult.build(400, "用户名不能为空！");
		}
		// 判断用户名是否重复
		PekkaResult pekkaResult = checkData(user.getUsername(), 1);
		if (!(boolean) pekkaResult.getData()) {
			return PekkaResult.build(400, "用户名重复");
		}
		// 判断密码是否为空
		if (StringUtils.isBlank(user.getPassword())) {
			return PekkaResult.build(400, "密码不能为空！");
		}
		// 判断手机号是否重复
		pekkaResult = checkData(user.getPhone(), 2);
		if (!(boolean) pekkaResult.getData()) {
			return PekkaResult.build(400, "手机号重复");
		}
		// 判断邮箱是否重复
		pekkaResult = checkData(user.getEmail(), 3);
		if (!(boolean) pekkaResult.getData()) {
			return PekkaResult.build(400, "邮箱重复");
		}
		// 补全pojo
		user.setCreated(new Date());
		user.setUpdated(new Date());
		// 密码进行md5加密
		String md5pass = DigestUtils.md5DigestAsHex(user.getPassword().getBytes());
		user.setPassword(md5pass);
		// 插入数据
		userMapper.insert(user);
		// 返回注册成功
		return PekkaResult.ok();
	}

	/**
	 * 登陆service
	 * 
	 * @param username
	 *            用户名
	 * @param password
	 *            密码
	 */
	@Override
	public PekkaResult login(String username, String password) {
		// 判断用户名和密码是否正确
		TbUserExample example = new TbUserExample();
		Criteria criteria = example.createCriteria();
		criteria.andUsernameEqualTo(username);
		List<TbUser> list = userMapper.selectByExample(example);
		if (list == null || list.size() == 0) {
			return PekkaResult.build(400, "用户名或密码不正确");
		}
		// 密码进行md5加密后再校验
		TbUser user = list.get(0);
		if (!DigestUtils.md5DigestAsHex(password.getBytes()).equals(user.getPassword())) {
			// 返回登陆失败
			return PekkaResult.build(400, "用户名或密码不正确");
		}
		// 生成token,使用uuid
		String token = UUID.randomUUID().toString();
		// 清空密码
		user.setPassword(null);
		// 把用户信息保存到redis,key是token,value是用户信息
		jedisClient.set(USER_SESSION + ":" + token, JsonUtils.objectToJson(user));
		// 设置key的过期时间
		jedisClient.expire(USER_SESSION + ":" + token, SESSION_EXPIRE);
		// 返回登陆成功,把token返回
		return PekkaResult.ok(token);
	}

	/**
	 * 根据token取得用户信息
	 * 
	 * @param token
	 *            token
	 */
	@Override
	public PekkaResult getUserByToken(String token) {
		String json = jedisClient.get(USER_SESSION + ":" + token);
		if (StringUtils.isBlank(json)) {
			return PekkaResult.build(400, "用户登陆已过期");
		}
		// 重置过期时间
		jedisClient.expire(USER_SESSION + ":" + token, SESSION_EXPIRE);
		TbUser user = JsonUtils.jsonToPojo(json, TbUser.class);
		return PekkaResult.ok(user);
	}

	/**
	 * 退出
	 */
	@Override
	public PekkaResult logOut(String token) {
		jedisClient.del(USER_SESSION + ":" + token);
		return PekkaResult.ok();
	}

}
