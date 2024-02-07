package sia.tacocloudauthorizationserver.Repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import sia.tacocloudauthorizationserver.Models.UserAuth;

public interface UserAuthRepository
        extends CrudRepository<UserAuth, Integer> {
    UserAuth findByUsername(String username);
}
