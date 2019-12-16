package io.spring.workshop.stockquotes;

import org.apache.commons.lang3.EnumUtils;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class SearchRequestValidator {
    public void validate(SearchRequest sr) {
        if(sr.getSymbols() == null || sr.getSymbols().isEmpty()){
            throw new GeneralException("no symbol(s) specified", ResponseStatus.ClientError );
        }
        if(sr.getSymbols().size() >= 5){
            throw new GeneralException("max symbol(s) limit of 5 exceeded", ResponseStatus.ClientError );
        }
        if(sr.getContent_types() != null){
            Set<String> validContentTypes = new HashSet<>();
            sr.getContent_types().forEach(contentType -> {
                if(EnumUtils.isValidEnum(ContentTypes.class, contentType)){
                    validContentTypes.add(contentType);
                }
            });
            if(validContentTypes.isEmpty()){
                throw new GeneralException("requires 1 or more valid content_types: "+ Arrays.toString(ContentTypes.values()), ResponseStatus.ClientError );
            } else {
                sr.setContent_types(validContentTypes);
            }
        }

    }
}
