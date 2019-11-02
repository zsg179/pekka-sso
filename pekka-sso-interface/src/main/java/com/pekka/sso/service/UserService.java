package com.pekka.sso.service;

import com.pekka.common.pojo.PekkaResult;
import com.pekka.pojo.TbUser;

public interface UserService {

	PekkaResult checkData(String data, int type);

	PekkaResult register(TbUser user);

	PekkaResult login(String username, String password);

	PekkaResult getUserByToken(String token);

	PekkaResult logOut(String token);
}
